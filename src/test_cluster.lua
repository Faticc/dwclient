package.path = package.path .. ";./?.lua"

local cfb8 = require("cfb8")

local BLOCK_SIZE = 14 * 1024
local WORKER_COUNT = 3
local key = string.char(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)

local function make_payload(size)
    local out = {}
    for i = 1, size do
        out[i] = string.char((i * 37 + math.floor(i / 251)) % 256)
    end
    return table.concat(out)
end

local function encrypt_all(plaintext)
    return cfb8.Stream.new(key):encrypt(plaintext)
end

local function decrypt_one_worker(ciphertext)
    return cfb8.Stream.new(key):decrypt(ciphertext)
end

-- A worker receives the shared AES key and the 16-byte CFB8 register immediately
-- before its chunk. The IV is not the AES key: it is only the worker's start state.
local function decrypt_worker_chunk(ciphertext, start_index, end_index)
    local iv = start_index == 1 and key or ciphertext:sub(start_index - 16, start_index - 1)
    local chunk = ciphertext:sub(start_index, end_index)
    return cfb8.Stream.new(key, iv):decrypt(chunk)
end

local function decrypt_three_workers(ciphertext)
    local results = {}
    local chunk_size = math.ceil(#ciphertext / WORKER_COUNT)
    for worker_id = 1, WORKER_COUNT do
        local start_index = (worker_id - 1) * chunk_size + 1
        local end_index = math.min(worker_id * chunk_size, #ciphertext)
        if start_index <= #ciphertext then
            results[worker_id] = decrypt_worker_chunk(ciphertext, start_index, end_index)
        end
    end
    return table.concat(results)
end

local function timed(label, fn)
    local start = os.clock()
    local result = fn()
    local elapsed = os.clock() - start
    print(string.format("%-24s %.3f sec", label, elapsed))
    return result
end

local plaintext = make_payload(BLOCK_SIZE)
local ciphertext = timed("encrypt 14 KiB", function()
    return encrypt_all(plaintext)
end)

print("ciphertext size: " .. #ciphertext .. " bytes")
print("workers: " .. WORKER_COUNT)
print("NOTE: 3-worker mode is sequential in this test process; real modem workers run concurrently.")

local one_worker = timed("decrypt with 1 worker", function()
    return decrypt_one_worker(ciphertext)
end)

local three_workers = timed("decrypt with 3 workers", function()
    return decrypt_three_workers(ciphertext)
end)

local one_ok = one_worker == plaintext
local three_ok = three_workers == plaintext
local same_ok = one_worker == three_workers

print("1-worker result: " .. (one_ok and "OK" or "FAIL"))
print("3-worker result: " .. (three_ok and "OK" or "FAIL"))
print("results identical: " .. (same_ok and "OK" or "FAIL"))

os.exit((one_ok and three_ok and same_ok) and 0 or 1)
