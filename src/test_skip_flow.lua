--[[
Сквозная проверка пропуска тел: игровой цикл должен довести рукопожатие FML до конца,
не расшифровав ни байта содержимого крупных пакетов.

    lua test_skip_flow.lua

Проверяется то, на чём легко ошибиться: пропуск меняет состояние потока шифрования, и
если он неточен, следующий же пакет прочитается мусором. Поэтому сервер здесь
настоящий по формату -- пакеты шифруются тем же cfb8, каким клиент их читает, -- и
среди них есть реестр в 45 КБ, ровно как на живом сервере.
]]
package.path = "./?.lua;" .. package.path

local written = {}
local to_read, read_pos = {}, 1
local fake_handle = {
    read = function(_, n)
        local pending = to_read[1]
        if not pending then return nil, "closed" end
        local chunk = pending:sub(read_pos, read_pos + n - 1)
        read_pos = read_pos + #chunk
        if read_pos > #pending then table.remove(to_read, 1); read_pos = 1 end
        return chunk
    end,
    write = function(_, d) written[#written + 1] = d; return true end,
    close = function() end,
}
package.loaded["component"] = {}
package.loaded["internet"] = { open = function() return fake_handle end }
package.loaded["computer"] = { totalMemory = function() return 2 ^ 21 end,
                               freeMemory = function() return 2 ^ 20 end,
                               uptime = function() return 0 end,
                               pullSignal = function() end }

local proto = require("mc_protocol")
local cfb8 = require("cfb8")
local connection = require("connection")

local SECRET = "0123456789abcdef"

-- Сервер: шифрует всё одним потоком, как настоящий.
local server = cfb8.Stream.new(SECRET)
local function frame(packet_id, payload)
    local body = proto.write_varint(packet_id) .. payload
    return proto.write_varint(#body) .. body
end
local function send_encrypted(data) to_read[#to_read + 1] = server:encrypt(data) end

local function custom_payload(channel, data)
    return frame(0x3F, proto.write_string(channel) .. proto.write_ushort(#data) .. data)
end

local failures = 0
local function check(label, got, expected)
    if got == expected then print("  ok   " .. label)
    else print(string.format("  FAIL %s: %s вместо %s", label, tostring(got), tostring(expected)))
        failures = failures + 1 end
end

-- Login Success, дальше рукопожатие и большой реестр.
to_read[#to_read + 1] = frame(0x02, proto.write_string("uuid") .. proto.write_string("Ник"))

local conn = connection.new("h", 1, { username = "Ник", uuid = "u", access_token = "t" },
    require("modlist"), function() end, function() end)
conn:connect()
conn.conn:enable_encryption(SECRET)   -- сервер и клиент договорились

send_encrypted(custom_payload("FML|HS", "\0\2\0\0\0\0"))          -- Server Hello
send_encrypted(custom_payload("FML|HS", "\2" .. proto.write_varint(0)))  -- Mod List
send_encrypted(custom_payload("FML|HS", "\6" .. string.rep("R", 45000)))  -- реестр, 45 КБ
send_encrypted(custom_payload("FML|HS", "\255\2"))
send_encrypted(custom_payload("FML|HS", "\255\3"))
send_encrypted(custom_payload("tabmod", string.rep("T", 8000)))    -- шумный мод: мимо
send_encrypted(frame(0x02, proto.write_string('{"text":"привет"}')))     -- чат ПОСЛЕ пропусков

local seen_chat
local reason = conn:run(function(raw) seen_chat = raw end)

check("рукопожатие FML завершено", conn.fml_handshake.done, true)
check("чат после пропущенных тел цел", seen_chat, '{"text":"привет"}')
check("прочитано пакетов", conn.packets, 7)
check("последний размер -- настоящий", conn.last_size and conn.last_size > 0, true)
print("  ..  соединение закрылось как ожидалось: " .. tostring(reason):sub(1, 40))

if failures > 0 then print("\n" .. failures .. " FAILED"); os.exit(1) end
print("\nok: тела пропускаются, поток шифрования не сбивается")
