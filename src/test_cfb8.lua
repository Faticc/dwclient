package.path = package.path .. ";./?.lua"
local cfb8 = require("cfb8")

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

-- Cross-checked against Python's cryptography library (already verified working
-- against the real server in the Python bot), not derived from a public spec vector.
local key = hex_to_bytes("000102030405060708090a0b0c0d0e0f")
local plaintext = "Hello, Minecraft protocol! This is a test of CFB8 mode across a longer message to catch register-shift bugs."
local expected_ct = "42ea5ed4daf864eae7ef5c17728310d5ecaf34e37de59a5240e722c65fde57530b8318b47cc8e0166046af0a3d0523118f5f8c8f8467437547d7a3de9427427142a1e20e398715ddeace2d750f25cd7ee2ca00f81957c6ebf24235f282b136799af23f7fb0050fccaacfbf70"

local enc = cfb8.Stream.new(key)
local got_ct = to_hex(enc:encrypt(plaintext))
print("encrypt got:      " .. got_ct)
print("encrypt expected: " .. expected_ct)
local enc_ok = got_ct == expected_ct

local dec = cfb8.Stream.new(key)
local got_pt = dec:decrypt(hex_to_bytes(expected_ct))
print("decrypt got:      " .. got_pt)
print("decrypt expected: " .. plaintext)
local dec_ok = got_pt == plaintext

-- Also check chunked processing (as would happen with real socket reads/writes)
-- produces the same result as one big call, since the register must carry across
-- calls correctly.
local enc2 = cfb8.Stream.new(key)
local part1 = enc2:encrypt(plaintext:sub(1, 7))
local part2 = enc2:encrypt(plaintext:sub(8))
local chunked_ok = (part1 .. part2) == hex_to_bytes(expected_ct)
print("chunked encrypt matches single-call: " .. tostring(chunked_ok))

os.exit((enc_ok and dec_ok and chunked_ok) and 0 or 1)
