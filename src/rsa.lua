--[[
Just enough DER/ASN.1 to pull (modulus, exponent) out of the X.509
SubjectPublicKeyInfo the server sends in Encryption Request, plus PKCS#1 v1.5 padding
and RSA encryption (public key, small e -- see bignum.lua's module comment on why
that's cheap even in pure Lua). No general ASN.1 support, no decoding of anything else
-- this is exactly, and only, what the vanilla login handshake needs.

Expected shape (RFC 5280 SubjectPublicKeyInfo wrapping an RFC 8017 RSAPublicKey):
    SEQUENCE {
        SEQUENCE { OID rsaEncryption, NULL }   -- AlgorithmIdentifier, ignored
        BIT STRING {                            -- unused-bits byte, then:
            SEQUENCE {
                INTEGER modulus
                INTEGER publicExponent
            }
        }
    }
]]
local bn = require("bignum")

local function read_length(der, pos)
    local first = string.byte(der, pos)
    pos = pos + 1
    if first < 0x80 then
        return first, pos
    end
    local num_bytes = first - 0x80
    local length = 0
    for _ = 1, num_bytes do
        length = length * 256 + string.byte(der, pos)
        pos = pos + 1
    end
    return length, pos
end

-- Returns tag, value (substring), position just past the value.
local function read_tlv(der, pos)
    local tag = string.byte(der, pos)
    pos = pos + 1
    local length, value_start = read_length(der, pos)
    local value = der:sub(value_start, value_start + length - 1)
    return tag, value, value_start + length
end

local TAG_SEQUENCE = 0x30
local TAG_INTEGER = 0x02
local TAG_BIT_STRING = 0x03

-- Strips a DER INTEGER's leading 0x00 sign-disambiguation byte, if present (RSA's
-- modulus/exponent are always non-negative, but DER INTEGER is signed, so a positive
-- value with its top bit set gets a leading zero byte to keep it from looking
-- negative -- that byte isn't part of the actual number).
local function strip_der_integer_padding(bytes)
    if #bytes > 1 and string.byte(bytes, 1) == 0x00 then
        return bytes:sub(2)
    end
    return bytes
end

-- der_bytes: the raw SubjectPublicKeyInfo DER blob (this is exactly what the vanilla
-- Encryption Request packet's "Public Key" field contains).
-- Returns n (bignum), e (bignum), modulus_byte_length (int).
local function parse_public_key(der_bytes)
    local outer_tag, outer_value = read_tlv(der_bytes, 1)
    assert(outer_tag == TAG_SEQUENCE, "expected outer SEQUENCE")

    local pos = 1
    local _alg_tag, _alg_value, next_pos = read_tlv(outer_value, pos)
    pos = next_pos

    local bitstring_tag, bitstring_value = read_tlv(outer_value, pos)
    assert(bitstring_tag == TAG_BIT_STRING, "expected BIT STRING")
    -- First byte of a BIT STRING's content is the "number of unused bits in the last
    -- byte" -- always 0 here since what follows is itself DER (a whole number of
    -- bytes).
    local rsa_key_der = bitstring_value:sub(2)

    local inner_tag, inner_value = read_tlv(rsa_key_der, 1)
    assert(inner_tag == TAG_SEQUENCE, "expected inner RSAPublicKey SEQUENCE")

    local ipos = 1
    local n_tag, n_bytes, n_next = read_tlv(inner_value, ipos)
    assert(n_tag == TAG_INTEGER, "expected modulus INTEGER")
    local e_tag, e_bytes = read_tlv(inner_value, n_next)
    assert(e_tag == TAG_INTEGER, "expected exponent INTEGER")

    n_bytes = strip_der_integer_padding(n_bytes)
    e_bytes = strip_der_integer_padding(e_bytes)

    return bn.from_bytes(n_bytes), bn.from_bytes(e_bytes), #n_bytes
end

-- PKCS#1 v1.5 encryption padding (block type 2, random nonzero padding bytes). Needs
-- a `random_byte` function (0..255) since Lua's stdlib math.random is not
-- cryptographically strong and OpenComputers' Data Card can supply real randomness
-- instead -- see main.lua for what's actually passed in.
local function pkcs1_pad(data, modulus_byte_length, random_byte)
    local pad_len = modulus_byte_length - 3 - #data
    assert(pad_len >= 8, "message too long for this RSA key size")
    local padding = {}
    for i = 1, pad_len do
        local b
        repeat
            b = random_byte()
        until b ~= 0
        padding[i] = string.char(b)
    end
    return "\0\2" .. table.concat(padding) .. "\0" .. data
end

-- Encrypts `plaintext` (e.g. the 16-byte shared secret, or the 4-byte verify token)
-- with the server's RSA public key. `random_byte()` must return a fresh random value
-- in 0..255 each call.
local function encrypt(n, e, modulus_byte_length, plaintext, random_byte, yield_fn)
    local padded = pkcs1_pad(plaintext, modulus_byte_length, random_byte)
    local m = bn.from_bytes(padded)
    local c = bn.modexp(m, e, n, yield_fn)
    return bn.to_bytes(c, modulus_byte_length)
end

return {
    parse_public_key = parse_public_key,
    encrypt = encrypt,
}
