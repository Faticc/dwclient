package.path = package.path .. ";./?.lua"
local aes = require("aes")

local function hex_to_bytes(hex)
    local out = {}
    for i = 1, #hex, 2 do
        out[#out + 1] = string.char(tonumber(hex:sub(i, i + 1), 16))
    end
    return table.concat(out)
end

local function to_hex(bytes)
    local out = {}
    for i = 1, #bytes do
        out[i] = string.format("%02x", string.byte(bytes, i))
    end
    return table.concat(out)
end

-- NIST FIPS-197 Appendix B / C.1 AES-128 test vector.
local key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
local plaintext = hex_to_bytes("00112233445566778899aabbccddeeff")
local expected = "69c4e0d86a7b0430d8cdb78070b4c55a"

local rk = aes.expand_key(key)
local got = to_hex(aes.encrypt_block(rk, plaintext))

print("got:      " .. got)
print("expected: " .. expected)
os.exit(got == expected and 0 or 1)
