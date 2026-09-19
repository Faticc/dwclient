--[[
Wire primitives (varint, strings, packet framing) and the AES/CFB8 encryption toggle,
built on top of an OpenComputers `internet.open(host, port)` handle -- see
https://github.com/MightyPirates/OpenComputers/blob/master-MC1.7.10/.../internet.lua :
the buffered handle's read(n) blocks (internally yielding via os.sleep) but may return
fewer than n bytes, exactly like a raw POSIX socket, so read_exact() below loops the
same way ghost_client's Python packet_io.py does.
]]
local cfb8 = require("cfb8")
local trace = require("trace")

local M = {}

-- Единственный настоящий способ уступить управление. os.sleep(0) и event.pull(0, ...)
-- им НЕ являются: оба считают дедлайн "сейчас + 0", сразу видят, что ждать нечего, и
-- выходят, ни разу не позвав computer.pullSignal. Программа, которая "уступает" так,
-- не уступает вовсе и рано или поздно ловит "too long without yielding".
-- require внутри, а не сверху: модуля "computer" нет под обычным Lua, а этот файл
-- грузят офлайновые тесты.
local function default_yield() require("computer").pullSignal(0) end

-- Уступка по часам, а не по счётчику вызовов.
--
-- Уступить в OpenComputers дёшево по вычислениям и дорого по времени: машина, отдавшая
-- управление, просыпается НЕ РАНЬШЕ следующего тика, то есть каждая уступка стоит 50 мс
-- независимо от того, нужна она была или нет. Считающий код зовёт уступку часто -- cfb8
-- каждые 64 байта, bignum каждые 64 итерации деления, -- и если каждый такой вызов и
-- правда уступает, 45 КБ реестра превращаются в 704 тика (35 секунд) чистого ожидания,
-- а RSA -- в минуты. Именно это выглядело как "клиент вообще не заходит".
--
-- Уступать надо не часто, а вовремя: сторож убивает после пяти секунд без уступки,
-- значит хватит одной раз в две. Обёртка пропускает вызовы, пока не подошёл срок, а
-- считающий код продолжает звать её как звал.
--
-- Для ожидания данных из сокета она НЕ годится: там уступка и есть цель -- поспать,
-- пока сервер молчит. Поэтому read_exact пользуется обычной.
local WATCHDOG_MARGIN = 2.0

function M.throttled(yield_fn, interval)
    local uptime = require("computer").uptime
    local last = uptime()
    interval = interval or WATCHDOG_MARGIN
    return function(done, total)
        local now = uptime()
        if now - last >= interval then
            last = now
            yield_fn(done, total)
        end
    end
end

-- `yield_fn` (optional) is called once per read
-- attempt below -- this loop is what actually blocks while idle waiting for the next
-- byte from the server (a bare os.sleep(0) has no event-name filter, so it can and
-- does silently swallow a pending key_down event before main.lua's own filtered
-- event.pull(0, "key_down") ever sees it; that starved typed chat/commands even once
-- the "too long without yielding" kick below was fixed, since every idle wait for the
-- next packet ran through here, not just large encrypted payloads).
function M.read_exact(handle, n, yield_fn)
    yield_fn = yield_fn or default_yield
    local chunks = {}
    local remaining = n
    while remaining > 0 do
        local chunk, err = handle:read(remaining)
        if chunk == nil then
            error("connection closed while reading " .. n .. " bytes (" .. remaining .. " left): " .. tostring(err))
        end
        if #chunk > 0 then
            chunks[#chunks + 1] = chunk
            remaining = remaining - #chunk
        end
        -- Yield once per read attempt, whether or not it returned data. Yielding only
        -- on a fully-empty read (an earlier version of this fix) still wasn't enough:
        -- OpenComputers' internet handle can hand back a large payload (this server's
        -- REGISTER/ModList/tab-list-sync packets run several KB to tens of KB) as many
        -- small but non-empty chunks in a row, and reading all of those back-to-back
        -- with zero yields in between can by itself exceed the "too long without
        -- yielding" watchdog window, even though no single read ever came back empty.
        yield_fn()
    end
    return table.concat(chunks)
end

function M.write_varint(value)
    value = value % 4294967296 -- wrap to unsigned 32-bit, matches the protocol's varint
    local out = {}
    repeat
        local byte = value % 128
        value = (value - byte) / 128
        if value ~= 0 then
            out[#out + 1] = string.char(byte + 128)
        else
            out[#out + 1] = string.char(byte)
        end
    until value == 0
    return table.concat(out)
end

function M.read_varint(handle)
    local value = 0
    local shift = 0
    while true do
        local byte = string.byte(M.read_exact(handle, 1))
        value = value + (byte % 128) * (2 ^ shift)
        if byte < 128 then break end
        shift = shift + 7
        if shift > 35 then error("VarInt too big") end
    end
    if value >= 2147483648 then value = value - 4294967296 end
    return value
end

function M.write_string(s)
    return M.write_varint(#s) .. s
end

function M.write_ushort(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
end

-- Big-endian signed 32-bit int, matching Java's DataOutput/ByteBuf.writeInt -- used for
-- fixed-width int fields outside the varint-framed ones (Keep Alive ids, and the FML
-- handshake's snapshot-identifier field, see fml.lua's encode_client_hello).
function M.write_int(value)
    value = value % 4294967296 -- wrap to unsigned 32-bit
    local b3 = value % 256; value = (value - b3) / 256
    local b2 = value % 256; value = (value - b2) / 256
    local b1 = value % 256; value = (value - b1) / 256
    local b0 = value % 256
    return string.char(b0, b1, b2, b3)
end

-- Reader over an already-fully-received packet body (a plain Lua string), mirroring
-- ghost_client's Python ByteReader -- keeps a cursor, used to pull fields back out
-- after read_packet() has framed one whole packet.
local ByteReader = {}
ByteReader.__index = ByteReader

function M.new_reader(data)
    return setmetatable({ data = data, pos = 1 }, ByteReader)
end

function ByteReader:read(n)
    local chunk = self.data:sub(self.pos, self.pos + n - 1)
    self.pos = self.pos + n
    return chunk
end

-- Big-endian signed 16-bit length prefix, used by 1.7.x's Custom Payload "data" field
-- and the login-encryption byte-array fields -- NOT a varint (that's a modern-protocol
-- thing; this era predates it for byte arrays).
function ByteReader:read_i16()
    local hi, lo = string.byte(self:read(2), 1, 2)
    local v = hi * 256 + lo
    if v >= 32768 then v = v - 65536 end
    return v
end

function ByteReader:read_varint()
    local value = 0
    local shift = 0
    while true do
        local byte = string.byte(self:read(1))
        value = value + (byte % 128) * (2 ^ shift)
        if byte < 128 then break end
        shift = shift + 7
    end
    if value >= 2147483648 then value = value - 4294967296 end
    return value
end

function ByteReader:read_string()
    local len = self:read_varint()
    return self:read(len)
end

function ByteReader:remaining()
    return self.data:sub(self.pos)
end

-- Connection: wraps the OC socket handle, adding length-prefixed packet framing and
-- an optional AES/CFB8 layer switched on after the encryption handshake (see
-- connection.lua). No compression exists in protocol version 5 (1.7.10).
local Connection = {}
Connection.__index = Connection

-- `yield_fn` (optional) is forwarded into the CFB8
-- streams so a multi-KB encrypted packet (this server's REGISTER/mod-list payloads run
-- into the tens of KB) gets yielded mid-decrypt/encrypt instead of only between whole
-- packets -- see cfb8.lua's Stream:_process for why that matters.
-- `yield_fn` -- уступка для ожидания данных: срабатывает каждый раз.
-- `cpu_yield` -- для расшифровки: та же уступка, но по часам (см. M.throttled).
function M.new_connection(handle, yield_fn, cpu_yield)
    yield_fn = yield_fn or default_yield
    return setmetatable({
        handle = handle,
        enc_in = nil,
        enc_out = nil,
        yield_fn = yield_fn,
        cpu_yield = cpu_yield or M.throttled(yield_fn),
    }, Connection)
end

function Connection:enable_encryption(shared_secret16)
    self.enc_in = cfb8.Stream.new(shared_secret16)
    self.enc_out = cfb8.Stream.new(shared_secret16)
end

-- Крупнее этого расшифровка заметна на глаз, и про неё стоит сказать вслух: на такой
-- машине это тысячи блоков AES подряд.
local TRACE_DECRYPT_OVER = 4096

function Connection:_raw_read(n)
    local data = M.read_exact(self.handle, n, self.yield_fn)
    if self.enc_in then
        local loud = trace.enabled() and n >= TRACE_DECRYPT_OVER
        if loud then trace.busy(string.format("расшифровка %d Б", n)) end
        data = self.enc_in:decrypt(data, self.cpu_yield)
        if loud then trace.done(string.format("расшифровано %d Б", n)) end
    end
    return data
end

function Connection:_read_varint_raw()
    -- Same shape as M.read_varint, but through the (possibly encrypted) connection.
    local value = 0
    local shift = 0
    while true do
        local byte = string.byte(self:_raw_read(1))
        value = value + (byte % 128) * (2 ^ shift)
        if byte < 128 then break end
        shift = shift + 7
    end
    if value >= 2147483648 then value = value - 4294967296 end
    return value
end

function Connection:read_packet()
    local length = self:_read_varint_raw()
    local raw = self:_raw_read(length)
    local reader = M.new_reader(raw)
    local packet_id = reader:read_varint()
    return packet_id, reader
end

function Connection:send_packet(packet_id, payload)
    payload = payload or ""
    local body = M.write_varint(packet_id) .. payload
    local framed = M.write_varint(#body) .. body
    if self.enc_out then
        framed = self.enc_out:encrypt(framed, self.cpu_yield)
    end
    local ok, err = self.handle:write(framed)
    if not ok then
        error("failed to send packet: " .. tostring(err))
    end
end

function Connection:close()
    self.handle:close()
end

return M
