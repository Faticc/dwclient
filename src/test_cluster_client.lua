package.path = package.path .. ";./?.lua"

-- cluster_client.lua unconditionally requires("component")/("event") (same pattern as
-- connection.lua/rng.lua -- see their headers): fine on real OpenComputers, but this
-- test runs on plain Lua, so stub both *before* anything requires them. The fake
-- Linked Card's send() runs the worker's own decrypt logic (mirroring
-- cluster_worker_bundle.lua's receive loop) synchronously and queues a
-- "modem_message" event -- enough to exercise the real request/response framing and
-- IV handoff without real hardware.
local cfb8_for_worker_stub = require("cfb8")
local event_queue = {}
local tunnel_addresses = { ["tunnel-1"] = "tunnel", ["tunnel-2"] = "tunnel", ["tunnel-3"] = "tunnel" }
local tunnel_proxies = {}
for address in pairs(tunnel_addresses) do
    tunnel_proxies[address] = {
        send = function(...)
            local args = { ... }
            local command, request_id, chunk_id, key, iv, chunk = args[1], args[2], args[3], args[4], args[5], args[6]
            local ok, plaintext = pcall(function()
                return cfb8_for_worker_stub.Stream.new(key, iv):decrypt(chunk)
            end)
            if ok then
                table.insert(event_queue, { "modem_message", "worker-local", address, 0, 0,
                    command .. "-result", request_id, chunk_id, plaintext })
            else
                table.insert(event_queue, { "modem_message", "worker-local", address, 0, 0,
                    command .. "-error", request_id, chunk_id, tostring(plaintext) })
            end
        end,
    }
end

package.loaded["component"] = {
    list = function(kind)
        if kind == "tunnel" then return tunnel_addresses end
        return {}
    end,
    proxy = function(address) return tunnel_proxies[address] end,
}
package.loaded["event"] = {
    pull = function(timeout, filter)
        if #event_queue == 0 then return nil end
        return table.unpack(table.remove(event_queue, 1))
    end,
}

local cfb8 = require("cfb8")
local cluster_client = require("cluster_client")

local key = string.char(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16)

local function make_payload(size, seed)
    local out = {}
    for i = 1, size do
        out[i] = string.char((i * 37 + seed + math.floor(i / 251)) % 256)
    end
    return table.concat(out)
end

-- Encrypt is always local (see cfb8.lua's Stream:decrypt comment for why encrypt
-- can't be parallelized this way) -- these are the "already on the wire" packets a
-- real connection would have received one at a time.
local enc_stream = cfb8.Stream.new(key)
local packets_plain = { make_payload(300, 1), make_payload(5000, 2), make_payload(50, 3), make_payload(9000, 4) }
local packets_cipher = {}
for i, p in ipairs(packets_plain) do
    packets_cipher[i] = enc_stream:encrypt(p)
end

local cluster = cluster_client.new({ min_size = 1024, chunk_size = 700 })
local all_ok = cluster:available() and #cluster.tunnels == 3
print("Linked Cards auto-detected: " .. #cluster.tunnels .. " (" .. (all_ok and "OK" or "FAIL") .. ")")

-- min_size=1024 with a mix of packet sizes above and below it exercises both the
-- cluster path and the local fallback, back to back, on the SAME Stream -- this is
-- the real thing to get right: the register has to hand off correctly across calls
-- regardless of which path decrypted the previous one.
local dec_stream = cfb8.Stream.new(key)
for i, c in ipairs(packets_cipher) do
    local got = dec_stream:decrypt(c, nil, cluster)
    local ok = got == packets_plain[i]
    print(string.format("packet %d (%d bytes, %s): %s", i, #c,
        (#c >= cluster.min_size) and "cluster" or "local", ok and "OK" or "FAIL"))
    if not ok then all_ok = false end
end

-- A Stream with no cluster argument at all (nil) must behave exactly as before this
-- feature existed -- the whole point of making `cluster` an optional 3rd argument.
local plain2 = make_payload(4000, 9)
local cipher2 = cfb8.Stream.new(key):encrypt(plain2)
local no_cluster_ok = cfb8.Stream.new(key):decrypt(cipher2) == plain2
print("no-cluster-arg path: " .. (no_cluster_ok and "OK" or "FAIL"))
if not no_cluster_ok then all_ok = false end

-- No Linked Cards installed at all must fall back cleanly too.
package.loaded["component"].list = function() return {} end
local empty_cluster = cluster_client.new()
local fallback_ok = not empty_cluster:available()
    and cfb8.Stream.new(key):decrypt(cipher2, nil, empty_cluster) == plain2
print("no-linked-cards fallback: " .. (fallback_ok and "OK" or "FAIL"))
if not fallback_ok then all_ok = false end

print("ALL: " .. (all_ok and "OK" or "FAIL"))
os.exit(all_ok and 0 or 1)
