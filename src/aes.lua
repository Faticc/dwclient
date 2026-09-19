--[[
Pure-Lua AES-128 *encryption only* (no decrypt round needed: CFB mode is built purely
from the block cipher's encrypt function in both directions -- see cfb8.lua). Uses the
classic 4-table ("T-table") construction so each round is a handful of table lookups
and XORs instead of per-byte GF(2^8) multiplication -- this matters here because the
Minecraft protocol's CFB8 mode needs one full AES block encryption per single byte of
traffic, and this server sends multi-kilobyte packets (a ~13KB custom-payload blob was
observed in practice), so the fast path isn't optional.
]]
local bit = require("bit_compat")
local bxor, band, rotl32 = bit.band and bit.bxor, bit.band, bit.rotl32
bxor = bit.bxor
local to_bytes32, from_bytes32 = bit.to_bytes32, bit.from_bytes32
local floor = math.floor

local SBOX = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
}

local RCON = {0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36}

-- GF(2^8) multiply-by-2 ("xtime") under the AES reduction polynomial.
local function xtime(x)
    local shifted = x * 2
    if x >= 0x80 then
        return bxor(shifted % 256, 0x1b)
    end
    return shifted
end

local function gmul(a, b)
    local p = 0
    for _ = 1, 8 do
        if b % 2 == 1 then p = bxor(p, a) end
        a = xtime(a)
        b = floor(b / 2)
    end
    return p
end

-- Te0..Te3: Te_k[x] is MixColumn(Sbox[x]) rotated so that byte position k of the
-- output word holds Sbox[x]*2, with the rest holding Sbox[x] or Sbox[x]*3 per the
-- standard AES MixColumns matrix, pre-rotated for each of the 4 table variants.
local Te0, Te1, Te2, Te3 = {}, {}, {}, {}
for x = 0, 255 do
    local s = SBOX[x + 1]
    local s2 = gmul(s, 2)
    local s3 = gmul(s, 3)
    -- word = [s2, s, s, s3] (byte0..byte3, most significant first)
    local w = from_bytes32(s2, s, s, s3)
    Te0[x] = w
    Te1[x] = bit.rotl32(w, 24)
    Te2[x] = bit.rotl32(w, 16)
    Te3[x] = bit.rotl32(w, 8)
end

-- Hoisted out of encrypt_block (below) so it's not a fresh closure allocation on
-- every single call -- encrypt_block runs once per byte of network traffic (CFB8),
-- so that allocation was happening tens of thousands of times per packet.
local function sb(x) return SBOX[x + 1] end

local function sub_word(w)
    local b0, b1, b2, b3 = to_bytes32(w)
    return from_bytes32(SBOX[b0 + 1], SBOX[b1 + 1], SBOX[b2 + 1], SBOX[b3 + 1])
end

-- AES-128 key expansion: 16-byte key -> 44 32-bit words (11 round keys).
local function expand_key(key16)
    assert(#key16 == 16, "AES-128 key must be 16 bytes")
    local w = {}
    for i = 0, 3 do
        local o = i * 4 + 1
        local b0, b1, b2, b3 = string.byte(key16, o, o + 3)
        w[i] = from_bytes32(b0, b1, b2, b3)
    end
    for i = 4, 43 do
        local temp = w[i - 1]
        if i % 4 == 0 then
            temp = bit.rotl32(temp, 8)
            temp = sub_word(temp)
            temp = bxor(temp, RCON[i / 4] * 0x1000000)
        end
        w[i] = bxor(w[i - 4], temp)
    end
    return w
end

-- The 9 main AES rounds (AddRoundKey+SubBytes+ShiftRows+MixColumns via T-tables),
-- shared by both entry points below. `rk` is the expanded key; s0..s3 must already
-- be the plaintext words XORed with rk[0..3] (initial AddRoundKey).
local function _rounds(rk, s0, s1, s2, s3)
    for round = 1, 9 do
        local ridx = round * 4
        local rk0, rk1, rk2, rk3 = rk[ridx], rk[ridx + 1], rk[ridx + 2], rk[ridx + 3]
        local a0, a1, a2, a3 = to_bytes32(s0)
        local c0, c1, c2, c3 = to_bytes32(s1)
        local d0, d1, d2, d3 = to_bytes32(s2)
        local e0, e1, e2, e3 = to_bytes32(s3)

        local n0 = bxor(bxor(bxor(Te0[a0], Te1[c1]), bxor(Te2[d2], Te3[e3])), rk0)
        local n1 = bxor(bxor(bxor(Te0[c0], Te1[d1]), bxor(Te2[e2], Te3[a3])), rk1)
        local n2 = bxor(bxor(bxor(Te0[d0], Te1[e1]), bxor(Te2[a2], Te3[c3])), rk2)
        local n3 = bxor(bxor(bxor(Te0[e0], Te1[a1]), bxor(Te2[c2], Te3[d3])), rk3)
        s0, s1, s2, s3 = n0, n1, n2, n3
    end
    return s0, s1, s2, s3
end

-- CFB8's hot path (cfb8.lua): the register is always 4 plain 32-bit words, never a
-- string, and CFB8 only ever needs the FIRST byte of the encrypted block (used as
-- the keystream byte -- see cfb8.lua's header comment). Split out from
-- encrypt_block below so this path skips both the type(...)=="string" check/branch
-- and computing/packing the 3 unused final-round words on every single call --
-- this runs once per byte of network traffic.
local function keystream_byte(rk, r0, r1, r2, r3)
    local s0, s1, s2, s3 = _rounds(rk, bxor(r0, rk[0]), bxor(r1, rk[1]), bxor(r2, rk[2]), bxor(r3, rk[3]))
    local a0 = to_bytes32(s0)
    local _, c1 = to_bytes32(s1)
    local _, _, d2 = to_bytes32(s2)
    local _, _, _, e3 = to_bytes32(s3)
    return floor(bxor(from_bytes32(sb(a0), sb(c1), sb(d2), sb(e3)), rk[40]) / 16777216)
end

-- Public/test entry point: 16-byte string in, 16-byte string out (see test_aes.lua).
-- Not on the CFB8 hot path (that's keystream_byte above) so the extra unpacking here
-- doesn't matter.
local function encrypt_block(rk, block16)
    local b0, b1, b2, b3 = string.byte(block16, 1, 4)
    local b4, b5, b6, b7 = string.byte(block16, 5, 8)
    local b8, b9, b10, b11 = string.byte(block16, 9, 12)
    local b12, b13, b14, b15 = string.byte(block16, 13, 16)
    local r0 = from_bytes32(b0, b1, b2, b3)
    local r1 = from_bytes32(b4, b5, b6, b7)
    local r2 = from_bytes32(b8, b9, b10, b11)
    local r3 = from_bytes32(b12, b13, b14, b15)

    local s0, s1, s2, s3 = _rounds(rk, bxor(r0, rk[0]), bxor(r1, rk[1]), bxor(r2, rk[2]), bxor(r3, rk[3]))

    -- Final round: SubBytes + ShiftRows (no MixColumns), then AddRoundKey.
    local a0, a1, a2, a3 = to_bytes32(s0)
    local c0, c1, c2, c3 = to_bytes32(s1)
    local d0, d1, d2, d3 = to_bytes32(s2)
    local e0, e1, e2, e3 = to_bytes32(s3)

    local f0 = bxor(from_bytes32(sb(a0), sb(c1), sb(d2), sb(e3)), rk[40])
    local f1 = bxor(from_bytes32(sb(c0), sb(d1), sb(e2), sb(a3)), rk[41])
    local f2 = bxor(from_bytes32(sb(d0), sb(e1), sb(a2), sb(c3)), rk[42])
    local f3 = bxor(from_bytes32(sb(e0), sb(a1), sb(c2), sb(d3)), rk[43])

    local o0, o1, o2, o3 = to_bytes32(f0)
    local o4, o5, o6, o7 = to_bytes32(f1)
    local o8, o9, o10, o11 = to_bytes32(f2)
    local o12, o13, o14, o15 = to_bytes32(f3)
    return string.char(o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15)
end

return {
    expand_key = expand_key,
    encrypt_block = encrypt_block,
    keystream_byte = keystream_byte,
}
