--[[
Client half of the 1.7.10 FML handshake, the Lua twin of ghost_client/fml.py -- same
discriminators, same message layout, same state machine, all taken from the real FML
source (see that file's header for the citation).

Two things differ from the Industrial pack's copy of this file:

  * Client Hello is the plain vanilla form. Industrial ships `metahandshakepatcher`,
    which mixins a 4-byte block/item registry checksum in ahead of the protocol-version
    byte; this pack has no such mod, so sending that version here would put four
    unexpected bytes in front of the protocol version.
  * The mod list and channel list come from modlist.lua / channels.lua, both generated
    from this client's own mods/ directory by ghost_client/tools/pack_scan.py.

Memory, because this runs on a computer with 192KB of RAM: the mod list is 164 entries
and the channel list 129, and both are needed exactly twice -- once to build the
REGISTER payload and once to build the ModList payload. So both payloads are encoded
once, up front, and `release()` then drops every table behind them. On a real OC
machine that is the difference between the handshake fitting and not.
]]
local proto = require("mc_protocol")
local trace = require("trace")

local M = {}

M.CHANNEL_REGISTER = "REGISTER"
M.CHANNEL_HS = "FML|HS"
M.CHANNEL_FML = "FML"

local FML_PROTOCOL_VERSION = 2

local DISC_SERVER_HELLO = 0
local DISC_CLIENT_HELLO = 1
local DISC_MOD_LIST = 2
-- The registry sync (block/item name -> numeric id) arrives where FML's own ModIdData
-- would, but NOT under ModIdData's discriminator 3: a capture of the real exchange has
-- it under 6, 45486 bytes, starting `06 03 d9 37 1a 02 "dwcity:Stonebrick_..."`. The
-- stock FMLHandshakeCodec in this pack's forge.jar registers 3, so the server has
-- replaced the message -- consistent with a pack that lifts the vanilla block/item id
-- ceiling and needs a wider registry format. Nothing here reads the registry, so rather
-- than pin one number we accept whichever turns up: every other discriminator in this
-- protocol is <= 2 or negative, so "3 or above, in this state" is unambiguous.
local DISC_MOD_ID_DATA = 3
local DISC_HANDSHAKE_ACK = -1

local ORD_WAITINGSERVERDATA = 2
local ORD_WAITINGSERVERCOMPLETE = 3
local ORD_PENDINGCOMPLETE = 4
local ORD_COMPLETE = 5

local function write_i8(v)
    if v < 0 then v = v + 256 end
    return string.char(v % 256)
end

-- REGISTER's payload is the channel names joined by NUL, with no other framing. FML|HS
-- and FML go first because FML itself always registers them.
local function encode_register(channels)
    local out = { M.CHANNEL_HS, M.CHANNEL_FML }
    for i = 1, #channels do
        local name = channels[i]
        if name ~= M.CHANNEL_HS and name ~= M.CHANNEL_FML then
            out[#out + 1] = name
        end
    end
    return table.concat(out, "\0")
end

local function encode_client_hello()
    return write_i8(DISC_CLIENT_HELLO) .. write_i8(FML_PROTOCOL_VERSION)
end

-- Built with a table + concat rather than repeated `..`: 164 entries means 328 string
-- joins, and doing those one at a time allocates (and then collects) an intermediate
-- string per entry, each one longer than the last.
local mod_count = 0

local function encode_mod_list(mods)
    local parts, n, count = {}, 1, 0
    for modid, version in pairs(mods) do
        count = count + 1
        parts[n] = proto.write_string(modid)
        parts[n + 1] = proto.write_string(version)
        n = n + 2
    end
    mod_count = count
    return write_i8(DISC_MOD_LIST) .. proto.write_varint(count) .. table.concat(parts)
end

local function encode_handshake_ack(phase)
    return write_i8(DISC_HANDSHAKE_ACK) .. write_i8(phase)
end

local FmlHandshake = {}
FmlHandshake.__index = FmlHandshake

-- M.new(local_mod_list, send_payload_fn, channels)
-- send_payload_fn(channel, data) must send a Custom Payload on that channel.
function M.new(local_mod_list, send_payload_fn, channels)
    return setmetatable({
        register_payload = encode_register(channels or require("channels")),
        mod_list_payload = encode_mod_list(local_mod_list),
        mod_count = mod_count,
        send_payload = send_payload_fn,
        state = "HELLO",
        done = false,
        restart_count = 0, -- bumped each time a lobby->backend handoff restarts us
    }, FmlHandshake)
end

-- Drop the two payload strings once the handshake is done. A lobby->backend handoff can
-- restart the handshake at any time, so this is NOT called automatically -- only call it
-- if you are sure no further Server Hello is coming (see main.lua, which waits for the
-- play state to settle first).
function FmlHandshake:release()
    self.register_payload = nil
    self.mod_list_payload = nil
end

function FmlHandshake:handle_payload(channel, data)
    if channel ~= M.CHANNEL_HS then
        return -- REGISTER and mod channels are informational here
    end
    -- Содержимое может прийти обрезанным: игровой цикл расшифровывает только начало
    -- пакета (см. mc_protocol.read_packet). Рукопожатию хватает первого байта, но если
    -- не пришло и его -- молчим, а не падаем.
    if #data == 0 then return end
    local reader = proto.new_reader(data)
    local discriminator = string.byte(reader:read(1))
    if discriminator >= 128 then discriminator = discriminator - 256 end
    self:_on_message(discriminator, reader)
end

function FmlHandshake:_on_message(discriminator, reader)
    if discriminator == DISC_SERVER_HELLO then
        -- A Server Hello can legitimately arrive more than once on one TCP connection:
        -- a BungeeCord/Velocity-style proxy (proxy-N.metalabsmc.net is exactly that)
        -- hands the client from a lobby to a backend mid-connection, and the backend
        -- runs its own handshake from scratch. So restart in every state, not just
        -- HELLO -- otherwise this message matches no other state's expected
        -- discriminator, is silently dropped, and the backend waits forever for a
        -- Client Hello that never comes, then closes the socket.
        if self.state ~= "HELLO" then
            self.restart_count = self.restart_count + 1
        end
        if not self.mod_list_payload then
            error("FML handshake restarted after release(): the mod list is gone")
        end
        trace.step(self.state == "HELLO" and "FML: Server Hello"
            or "FML: Server Hello заново (передача на другой сервер)")
        if self.state == "HELLO" then
            self.send_payload(M.CHANNEL_REGISTER, self.register_payload)
            trace.step(string.format("FML: объявил каналы (%d Б) и %d модов (%d Б)",
                #self.register_payload, self.mod_count, #self.mod_list_payload))
        end
        self.send_payload(M.CHANNEL_HS, encode_client_hello())
        self.send_payload(M.CHANNEL_HS, self.mod_list_payload)
        self.state = "WAITINGSERVERDATA"
        self.done = false
    elseif self.state == "WAITINGSERVERDATA" then
        if discriminator ~= DISC_MOD_LIST then return end
        trace.step("FML: получил список модов сервера")
        self.send_payload(M.CHANNEL_HS, encode_handshake_ack(ORD_WAITINGSERVERDATA))
        self.state = "WAITINGSERVERCOMPLETE"
    elseif self.state == "WAITINGSERVERCOMPLETE" then
        if discriminator < DISC_MOD_ID_DATA then return end -- an ack, or a stray message
        trace.step("FML: получил реестр блоков и предметов")
        -- A real client reconciles block/item numeric ids here. Nothing here tracks
        -- world state, so there is nothing to reconcile -- just acknowledge.
        self.send_payload(M.CHANNEL_HS, encode_handshake_ack(ORD_WAITINGSERVERCOMPLETE))
        self.state = "PENDINGCOMPLETE"
    elseif self.state == "PENDINGCOMPLETE" then
        self.send_payload(M.CHANNEL_HS, encode_handshake_ack(ORD_PENDINGCOMPLETE))
        self.state = "COMPLETE"
    elseif self.state == "COMPLETE" then
        self.send_payload(M.CHANNEL_HS, encode_handshake_ack(ORD_COMPLETE))
        self.state = "DONE"
        self.done = true
        trace.step("FML: рукопожатие завершено")
    end
end

return M
