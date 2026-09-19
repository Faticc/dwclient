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

function M.write_string(s)
    return M.write_varint(#s) .. s
end

function M.write_ushort(n)
    return string.char(math.floor(n / 256) % 256, n % 256)
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
        buf = "",      -- прочитанный из сокета шифротекст, ещё не разобранный
        buf_pos = 1,
    }, Connection)
end

function Connection:enable_encryption(shared_secret16)
    self.enc_in = cfb8.Stream.new(shared_secret16)
    self.enc_out = cfb8.Stream.new(shared_secret16)
end

-- Крупнее этого расшифровка заметна на глаз, и про неё стоит сказать вслух: на такой
-- машине это тысячи блоков AES подряд.
local TRACE_DECRYPT_OVER = 4096

-- Сколько просить у карты за один раз. Каждое обращение к компоненту тратит бюджет
-- тика, а длина пакета -- это варинт, то есть до пяти байт: читать их по одному значило
-- бы до шести вызовов на пакет при ста семидесяти пакетах в секунду. Буфер сводит это к
-- одному вызову на несколько килобайт.
local READ_CHUNK = 8192

-- Держит в буфере хотя бы n байт шифротекста.
function Connection:_fill(n)
    local have = #self.buf - self.buf_pos + 1
    while have < n do
        local want = n - have
        if want < READ_CHUNK then want = READ_CHUNK end
        local chunk, err = self.handle:read(want)
        if chunk == nil then
            error("connection closed while reading " .. n .. " bytes (" .. (n - have) .. " left): " .. tostring(err))
        end
        if #chunk > 0 then
            -- Разобранное отрезается здесь, а не на каждом take: строки в Lua
            -- неизменяемы, и подрезать на каждый байт значило бы копировать буфер.
            if self.buf_pos > 1 then
                self.buf = self.buf:sub(self.buf_pos)
                self.buf_pos = 1
            end
            self.buf = self.buf .. chunk
            have = #self.buf - self.buf_pos + 1
            if have < n and self.cpu_yield then self.cpu_yield() end
        else
            self.yield_fn() -- данных нет: вот теперь и правда спим
        end
    end
end

function Connection:_take(n)
    self:_fill(n)
    local out = self.buf:sub(self.buf_pos, self.buf_pos + n - 1)
    self.buf_pos = self.buf_pos + n
    return out
end

function Connection:_raw_read(n)
    local data = self:_take(n)
    if self.enc_in then
        data = self.enc_in:decrypt(data, self.cpu_yield)
    end
    return data
end

function Connection:_read_varint_raw()
    -- Множитель вместо 2^shift: в Lua 5.3 возведение в степень всегда даёт дробное
    -- число, и длина пакета выходила "4106.0". Само по себе безобидно, но дробные
    -- дальше идут в арифметику и в сообщения об ошибках, а целые ещё и быстрее.
    local value, mult = 0, 1
    while true do
        local byte = string.byte(self:_raw_read(1))
        value = value + (byte % 128) * mult
        if byte < 128 then break end
        mult = mult * 128
    end
    if value >= 2147483648 then value = value - 4294967296 end
    return value
end

-- Сколько байт пакета расшифровывается всегда, до решения "нужен ли он целиком".
-- Хватает на id пакета, имя канала и первый байт содержимого -- этого довольно, чтобы
-- решить; для FML|HS этого довольно и чтобы ответить.
local HEAD_BYTES = 96

-- `wants(packet_id)` отвечает, сколько пакета нужно:
--
--   "full" -- всё содержимое (чат, keep-alive: они маленькие)
--   "head" -- только начало: хватит на имя канала и первый байт содержимого
--   "skip" -- ничего; поток прокручивается по шифротексту, без единого блока AES
--
-- Решение принимается ПОСЛЕ расшифровки одного байта -- id пакета. Это важнее, чем
-- кажется: сервер шлёт около 170 пакетов в секунду, почти все на модовых каналах,
-- которые клиенту не нужны совсем. Расшифровывать у каждого хотя бы начало значило бы
-- под сотню блоков AES на пакет впустую; так их один.
--
-- Все игровые id версии 1.7.10 меньше 0x80, то есть занимают ровно один байт varint.
function Connection:read_packet(wants)
    local length = self:_read_varint_raw()
    self.last_length = length

    if not self.enc_in then
        local reader = M.new_reader(self:_take(length))
        return reader:read_varint(), reader
    end

    local raw = self:_take(length)
    local first = self.enc_in:decrypt(raw:sub(1, 1), self.cpu_yield)
    local packet_id = string.byte(first)

    local mode = wants and wants(packet_id) or "full"
    if mode == "skip" then
        if length > 1 then self.enc_in:skip(raw:sub(2)) end
        return packet_id, nil, true
    end

    local want_n = length
    if mode == "head" and HEAD_BYTES < length then want_n = HEAD_BYTES end

    local body = first
    if want_n > 1 then
        local loud = trace.enabled() and want_n >= TRACE_DECRYPT_OVER
        if loud then trace.busy(string.format("расшифровка %d Б", want_n)) end
        body = first .. self.enc_in:decrypt(raw:sub(2, want_n), self.cpu_yield)
        if loud then trace.done(string.format("расшифровано %d Б", want_n)) end
    end
    if want_n < length then self.enc_in:skip(raw:sub(want_n + 1)) end

    -- Читатель отдаётся стоящим сразу за id пакета -- как и на пути без шифрования.
    local reader = M.new_reader(body)
    reader:read_varint()
    return packet_id, reader, want_n < length
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
