package.path = package.path .. ";./?.lua"
local rsa = require("rsa")
local bn = require("bignum")

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

-- Real 1024-bit key generated with Python's `cryptography` for this test.
local n_hex = "c796a30ef113bbfc9e1dc8d4f1dda00c3376d629b9906af247ef073a26b3e84b190e143b1b7cc34eb9fbc9b1c259548f2da47ad99f82d60a9e1e407513d6a4f699e64c1626c6f3f21d832a103fa1823f313328e3fe671356c997e12504d1e1aae886714b8c4e522b776a749fb62c69395ed5108aaf31306f9119c22f8bda0d81"
local der_hex = "30819f300d06092a864886f70d010101050003818d0030818902818100c796a30ef113bbfc9e1dc8d4f1dda00c3376d629b9906af247ef073a26b3e84b190e143b1b7cc34eb9fbc9b1c259548f2da47ad99f82d60a9e1e407513d6a4f699e64c1626c6f3f21d832a103fa1823f313328e3fe671356c997e12504d1e1aae886714b8c4e522b776a749fb62c69395ed5108aaf31306f9119c22f8bda0d810203010001"

local der_bytes = hex_to_bytes(der_hex)
local n, e, mod_len = rsa.parse_public_key(der_bytes)

local ok_n = to_hex(bn.to_bytes(n)) == n_hex
local ok_e = bn.compare(e, bn.from_int(65537)) == 0
print("parsed n matches: " .. tostring(ok_n))
print("parsed e matches: " .. tostring(ok_e))
print("modulus byte length: " .. mod_len)

-- Deterministic "random" bytes for reproducibility -- a real client must use a real
-- CSPRNG here (OpenComputers' Data Card has one), this is purely for the test.
local seed = 12345
local function fake_random_byte()
    seed = (seed * 1103515245 + 12345) % 2147483648
    return seed % 256
end

local plaintext = "0123456789abcdef" -- 16 bytes, like a real shared secret
local ciphertext = rsa.encrypt(n, e, mod_len, plaintext, fake_random_byte)
print("ciphertext_hex: " .. to_hex(ciphertext))

-- Write it out so Python can decrypt it with the matching private key and confirm
-- the plaintext round-trips.
local f = io.open(os.getenv("TEMP") .. "\\ghost_lua_rsa_ciphertext.hex", "w")
f:write(to_hex(ciphertext))
f:close()

os.exit((ok_n and ok_e) and 0 or 1)
