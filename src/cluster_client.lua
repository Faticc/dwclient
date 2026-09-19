--[[
Client-side counterpart to the tunnel-based cluster worker: splits a big AES/CFB8
ciphertext buffer across a pool of Linked Cards (OpenComputers "tunnel" components,
https://ocdoc.cil.li/component:tunnel) instead of decrypting it all on this computer.

Linked Cards on purpose, not Network Cards/modems: a Linked Card pair is a fixed
point-to-point link crafted once -- no wireless range, no coordinates, no addressing
by a remote UUID needed. `tunnel.send(...)` always goes to whichever card(s) this one
was linked with, and Linked Cards fire the same `modem_message` signal shape network
cards do (same doc), just with a meaningless port/distance (there's no `open`/`close`
port concept for a tunnel at all). So "the worker pool" here is simply every `tunnel`
component this computer has plugged in -- each one is physically wired, at crafting
time, to exactly one worker computer's own Linked Card. Round-robin across
`component.list("tunnel")` plays the same role a WORKERS address list plays for
modems: chunk N goes out through tunnel (N mod #tunnels) + 1.

Only *decrypt* is offered here, not encrypt: CFB8 encryption is inherently serial --
chunk N+1's IV is the *ciphertext output* of chunk N, which isn't known until chunk N
has actually been encrypted, so there's no way to hand independent chunks to
independent workers without either breaking the stream or making them wait on each
other anyway. Decryption doesn't have that problem: by the time we're decrypting, the
whole ciphertext buffer already arrived over the network, so chunk N+1's IV (the 16
ciphertext bytes right before it) is already sitting right there in the buffer -- no
serial dependency, so real parallelism is possible. See cfb8.lua's Stream:decrypt.
]]
local component = require("component")
local event = require("event")

local M = {}
local Cluster = {}
Cluster.__index = Cluster

-- opts (all optional): chunk_size (bytes per tunnel message, default 1024), min_size
-- (below this many bytes the round-trip messaging overhead isn't worth it -- decrypt
-- locally instead; default 2048), timeout (seconds to wait for all chunks before
-- giving up, default 5), command (must match the worker's, default
-- "ghost-cfb8-decrypt").
function M.new(opts)
    opts = opts or {}
    local tunnels = {}
    local ok, addresses = pcall(component.list, "tunnel")
    if ok and addresses then
        for address in pairs(addresses) do
            local proxy_ok, proxy = pcall(component.proxy, address)
            if proxy_ok and proxy then
                tunnels[#tunnels + 1] = proxy
            end
        end
    end
    return setmetatable({
        tunnels = tunnels,
        chunk_size = opts.chunk_size or 1024,
        min_size = opts.min_size or 2048,
        timeout = opts.timeout or 5,
        command = opts.command or "ghost-cfb8-decrypt",
        request_seq = 0,
    }, Cluster)
end

-- False with no Linked Cards plugged into this computer -- Stream:decrypt falls back
-- to local decryption transparently.
function Cluster:available()
    return #self.tunnels > 0
end

function Cluster:_next_request_id()
    self.request_seq = self.request_seq + 1
    return tostring(os.time()) .. "-" .. tostring(self.request_seq)
end

-- Same chunking idea as a modem-based master: chunk 1's IV is `iv0` (the caller's
-- current CFB8 register, i.e. the state right before this buffer started); every
-- later chunk's IV is just the 16 ciphertext bytes right before it, already sitting
-- in `ciphertext` since it's a complete, already-received buffer. Each chunk goes
-- out through a different tunnel in round-robin order -- each tunnel IS a specific
-- worker (see the header comment), there's no address to pick.
function Cluster:_send_chunks(ciphertext, key, iv0, request_id)
    local chunk_count = math.ceil(#ciphertext / self.chunk_size)
    for chunk_id = 1, chunk_count do
        local start_index = (chunk_id - 1) * self.chunk_size + 1
        local end_index = math.min(chunk_id * self.chunk_size, #ciphertext)
        local tunnel = self.tunnels[((chunk_id - 1) % #self.tunnels) + 1]
        local iv = start_index == 1 and iv0 or ciphertext:sub(start_index - 16, start_index - 1)
        local chunk = ciphertext:sub(start_index, end_index)
        tunnel.send(self.command, request_id, chunk_id, key, iv, chunk)
    end
    return chunk_count
end

-- Linked Cards fire the same modem_message signal shape network cards do, but
-- port/distance are meaningless for a point-to-point link (no `open()` concept
-- either), so -- unlike a modem-based version -- this deliberately does NOT filter
-- on them, only on the command name and request_id we put in the payload ourselves.
function Cluster:_receive_chunks(chunk_count, request_id, yield_fn)
    local results = {}
    local received = 0
    local deadline = os.clock() + self.timeout
    while received < chunk_count do
        if os.clock() >= deadline then
            error("cluster decrypt timed out: " .. received .. "/" .. chunk_count .. " chunks")
        end
        local _, _, _, _, _, message_type, req_id, chunk_id, payload = event.pull(1, "modem_message")
        if message_type == self.command .. "-error" and req_id == request_id then
            error("cluster worker reported error on chunk " .. tostring(chunk_id) .. ": " .. tostring(payload))
        elseif message_type == self.command .. "-result" and req_id == request_id and results[chunk_id] == nil then
            results[chunk_id] = payload
            received = received + 1
        end
        if yield_fn then yield_fn() end
    end
    return table.concat(results)
end

-- Decrypts `ciphertext` (AES/CFB8; `key` is the 16-byte shared secret, `iv0` is the
-- 16-byte register state immediately before `ciphertext`'s first byte) across the
-- worker pool, returning the plaintext. Raises on any failure (no Linked Cards,
-- timeout, a worker reporting an error) rather than silently falling back -- callers
-- (cfb8.lua's Stream:decrypt) are expected to pcall this and fall back to local
-- decryption themselves, since only they know whether the register still needs
-- updating for the failed attempt.
function Cluster:decrypt(ciphertext, key, iv0, yield_fn)
    if not self:available() then
        error("cluster decrypt requested but no Linked Cards (tunnel components) found")
    end
    local request_id = self:_next_request_id()
    local chunk_count = self:_send_chunks(ciphertext, key, iv0, request_id)
    return self:_receive_chunks(chunk_count, request_id, yield_fn)
end

return M
