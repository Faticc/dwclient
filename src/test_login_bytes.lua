--[[
Drives the login sequence against a stubbed OpenComputers environment and prints the
bytes it would put on the wire, so they can be diffed against the Python client's --
which is the one proven to get into the server.

    lua test_login_bytes.lua

Checks, in order:
  * Login Start really is locale + username + eight writeUTF fields, and the whole
    packet matches the Python client byte for byte;
  * the FML handshake answers a Server Hello with REGISTER + Client Hello + Mod List,
    with the Client Hello in its plain vanilla two-byte form;
  * the registry message under discriminator 6 (not FML's own 3) is acknowledged rather
    than ignored -- the bug that used to leave the handshake stuck forever;
  * fml.new() really does let go of the mod list and channel tables afterwards.

This runs under plain Lua 5.4 with no OpenComputers around, which is the point: it can
be run on the machine that edits the code, in a second, as often as it takes.
]]

package.path = "./?.lua;" .. package.path

-- ---------------------------------------------------------------------------
-- Stub the OpenComputers side: a socket that records what was written and replays a
-- canned Login Success, so connect() runs to completion without encryption.
-- ---------------------------------------------------------------------------
local written = {}
local to_read = {}
local read_pos = 1

local function queue(data) to_read[#to_read + 1] = data end

local fake_handle = {
    read = function(self, n)
        local pending = to_read[1]
        if not pending then return nil, "closed" end
        local chunk = pending:sub(read_pos, read_pos + n - 1)
        read_pos = read_pos + #chunk
        if read_pos > #pending then
            table.remove(to_read, 1)
            read_pos = 1
        end
        return chunk
    end,
    write = function(self, data) written[#written + 1] = data; return true end,
    close = function() end,
}

-- The real hwid.lua is used, not a stand-in: it ships with the client, and with it in
-- place the packet this builds matches the Python client's byte for byte -- which is how
-- the wire format was confirmed in the first place. Regenerating hwid.lua with another
-- seed changes the field lengths but not the framing, so this still passes.
package.loaded["component"] = {}
package.loaded["internet"] = { open = function() return fake_handle end }
package.loaded["computer"] = { totalMemory = function() return 196608 end,
                               freeMemory = function() return 98304 end,
                               uptime = function() return 0 end }
if not os.sleep then os.sleep = function() end end

-- ---------------------------------------------------------------------------
local proto = require("mc_protocol")

local function varint(value)
    return proto.write_varint(value)
end

local function frame(packet_id, payload)
    local body = varint(packet_id) .. (payload or "")
    return varint(#body) .. body
end

local function hex(s)
    return (s:gsub(".", function(c) return string.format("%02x", string.byte(c)) end))
end

local failures = 0
local function check(label, got, expected)
    if got == expected then
        print("  ok   " .. label)
    else
        print("  FAIL " .. label)
        print("         got " .. tostring(got))
        print("    expected " .. tostring(expected))
        failures = failures + 1
    end
end

-- Login Success: uuid string + username string, and nothing else.
queue(frame(0x02, proto.write_string("00000000-0000-0000-0000-000000000000")
    .. proto.write_string("YourNick")))

local connection = require("connection")
local conn = connection.new("proxy-1.metalabsmc.net", 25606,
    { username = "YourNick", uuid = "00000000-0000-0000-0000-000000000000", access_token = "x" },
    require("modlist"),
    function() error("join_server must not be called: this stub never asks for encryption") end,
    function() end, nil)

conn:connect()

print("packets written during login: " .. #written)
local handshake, login_start = written[1], written[2]

-- Peel the frame off Login Start: length varint, packet id varint, then the body.
local reader = proto.new_reader(login_start)
local total = reader:read_varint()
local packet_id = reader:read_varint()
print("\nLogin Start:")
check("packet id is 0x00", packet_id, 0x00)
local locale = reader:read_string()
local username = reader:read_string()
check("locale comes first", locale, "ru_RU")
check("username comes second", username, "YourNick")

local extras = reader:remaining()
local count, pos = 0, 1
while pos <= #extras do
    local hi, lo = string.byte(extras, pos, pos + 1)
    local length = hi * 256 + lo
    local field = extras:sub(pos + 2, pos + 1 + length)
    count = count + 1
    if count == 1 then
        check("first field starts with \\1", field:sub(1, 1), "\1")
    end
    pos = pos + 2 + length
end
check("eight writeUTF fields", count, 8)
check("fields consume the packet exactly", pos - 1, #extras)
check("frame length matches", total, #login_start - #varint(total))

print("\nLOGIN_START_HEX " .. hex(login_start))

-- ---------------------------------------------------------------------------
-- FML handshake
-- ---------------------------------------------------------------------------
print("\nFML handshake:")
check("mod list table released", conn.local_mod_list, nil)
check("modlist module unloaded", package.loaded["modlist"], nil)
check("channels module unloaded", package.loaded["channels"], nil)

local sent = {}
local handshake_obj = conn.fml_handshake
handshake_obj.send_payload = function(channel, data) sent[#sent + 1] = { channel, data } end

-- Server Hello: protocol 2, then a 4-byte dimension.
handshake_obj:handle_payload("FML|HS", "\0\2\0\0\0\0")
check("three payloads answer a Server Hello", #sent, 3)
check("first is REGISTER", sent[1][1], "REGISTER")
check("REGISTER starts with FML|HS", sent[1][2]:sub(1, 6), "FML|HS")
check("Client Hello is vanilla two bytes", hex(sent[2][2]), "0102")
check("Mod List discriminator", hex(sent[3][2]:sub(1, 1)), "02")

-- Server's Mod List -> we ack phase 2.
sent = {}
handshake_obj:handle_payload("FML|HS", "\2" .. varint(0))
check("ack after Mod List", hex(sent[1][2]), "ff02")

-- The registry, under discriminator 6 rather than FML's own 3.
sent = {}
handshake_obj:handle_payload("FML|HS", "\6" .. string.rep("\0", 32))
check("registry under disc 6 is acknowledged", hex(sent[1][2]), "ff03")

sent = {}
handshake_obj:handle_payload("FML|HS", "\255\2")
check("pending complete", hex(sent[1][2]), "ff04")
sent = {}
handshake_obj:handle_payload("FML|HS", "\255\3")
check("complete", hex(sent[1][2]), "ff05")
check("handshake finished", handshake_obj.done, true)

print("")
if failures > 0 then
    print(failures .. " FAILED")
    os.exit(1)
end
print("all checks passed")
