--[[
AES/CFB8/NoPadding, matching Java's Cipher.getInstance("AES/CFB8/NoPadding") which the
vanilla Minecraft client uses once encryption is switched on. Built purely from
aes.encrypt_block (CFB needs only the block cipher's *encrypt* direction, even when
decrypting the stream -- see the feedback rule below).

Per-byte rule (same for both directions): the 16-byte "register" starts as the shared
secret (used as both AES key and initial IV, per the vanilla protocol). For each byte:
    keystream_byte = AES_encrypt(key, register)[0]        -- first byte only
    out_byte       = in_byte XOR keystream_byte
    register       = register[2:16] .. ciphertext_byte     -- shift in the CIPHERTEXT byte

That last line is the same on encrypt and decrypt: the feedback is always the
*ciphertext* byte (on encrypt, ciphertext_byte == out_byte; on decrypt, it's the
in_byte). Encryption and decryption therefore need two independent stream objects
(one per direction), each seeded with the same secret, since a real connection has
one Cipher instance per direction with its own internal state.
]]
local aes = require("aes")
local bit = require("bit_compat")
local bxor = bit.bxor
local bor = bit.bor
local lshift32 = bit.lshift32
local rshift32 = bit.rshift32

local Stream = {}
Stream.__index = Stream

-- Packs/unpacks the 4 32-bit register words <-> the 16-byte string form used both as
-- the initial CFB8 IV.
local function bytes16_to_regs(bytes16)
    local b0, b1, b2, b3 = string.byte(bytes16, 1, 4)
    local b4, b5, b6, b7 = string.byte(bytes16, 5, 8)
    local b8, b9, b10, b11 = string.byte(bytes16, 9, 12)
    local b12, b13, b14, b15 = string.byte(bytes16, 13, 16)
    return bit.from_bytes32(b0, b1, b2, b3), bit.from_bytes32(b4, b5, b6, b7),
        bit.from_bytes32(b8, b9, b10, b11), bit.from_bytes32(b12, b13, b14, b15)
end

local function regs_to_bytes16(r0, r1, r2, r3)
    local to_bytes = bit.to_bytes32
    local a0, a1, a2, a3 = to_bytes(r0)
    local a4, a5, a6, a7 = to_bytes(r1)
    local a8, a9, a10, a11 = to_bytes(r2)
    local a12, a13, a14, a15 = to_bytes(r3)
    return string.char(a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15)
end

function Stream.new(shared_secret16, initial_register16)
    assert(#shared_secret16 == 16, "shared secret must be 16 bytes")
    initial_register16 = initial_register16 or shared_secret16
    assert(#initial_register16 == 16, "initial CFB8 register must be 16 bytes")
    local r0, r1, r2, r3 = bytes16_to_regs(initial_register16)
    return setmetatable({
        rk = aes.expand_key(shared_secret16),
        r0 = r0, r1 = r1, r2 = r2, r3 = r3,
    }, Stream)
end

-- Advances the stream over `data`, in the given direction, returning the transformed
-- bytes. `is_decrypt` selects which byte (input vs output) is fed back into the
-- register -- everything else is identical between the two directions.
--
-- `yield_fn`, if given, is called every YIELD_EVERY bytes: CFB8 needs one full AES
-- block encryption per single byte, and this server's REGISTER/mod-list custom-payload
-- packets run into the tens of KB (see aes.lua's header comment) -- running that whole
-- pass in one uninterrupted Lua loop, with no yield at all, is exactly what trips
-- OpenComputers' "too long without yielding" watchdog (this was observed live: the
-- surrounding packet-read loop already yields once per packet, but never mid-packet).
local YIELD_EVERY = 64

function Stream:_process(data, is_decrypt, yield_fn)
    local out = {}
    local n = #data
    local rk = self.rk
    local keystream_byte = aes.keystream_byte
    local char = string.char
    local r0, r1, r2, r3 = self.r0, self.r1, self.r2, self.r3
    for i = 1, n do
        local ks_byte = keystream_byte(rk, r0, r1, r2, r3)
        local in_byte = string.byte(data, i)
        local out_byte = bxor(in_byte, ks_byte)
        local feedback_byte = is_decrypt and in_byte or out_byte
        r0 = bor(lshift32(r0, 8), rshift32(r1, 24))
        r1 = bor(lshift32(r1, 8), rshift32(r2, 24))
        r2 = bor(lshift32(r2, 8), rshift32(r3, 24))
        r3 = bor(lshift32(r3, 8), feedback_byte)
        out[i] = char(out_byte)
        if yield_fn and i % YIELD_EVERY == 0 then
            self.r0, self.r1, self.r2, self.r3 = r0, r1, r2, r3
            -- Сколько уже сделано и сколько всего -- чтобы уступка могла показать
            -- прогресс. Кто не хочет, просто игнорирует доводы.
            yield_fn(i, n)
        end
    end
    self.r0, self.r1, self.r2, self.r3 = r0, r1, r2, r3
    return table.concat(out)
end

-- Пройти шифротекст, НЕ расшифровывая его: регистр сдвигается, открытый текст не
-- считается.
--
-- Это не оптимизация "на глазок", а прямое следствие правила выше: при расшифровке в
-- регистр вдвигается входной байт, то есть сам шифротекст. Ключевой поток нужен только
-- чтобы получить открытый текст, а на состояние потока он не влияет вовсе. Значит для
-- пакета, содержимое которого не нужно, весь AES -- лишняя работа, и её можно не делать,
-- оставшись ровно в том же состоянии.
--
-- Разница не косметическая. Реестр блоков и предметов приходит одним пакетом на 45 КБ,
-- клиент его не читает (он не следит за миром) -- а это 45 тысяч блоков AES на чистом
-- Lua, десятки секунд на машине OpenComputers. Здесь их ноль.
--
-- Работает только на расшифровке: при шифровании в регистр вдвигается ВЫХОДНОЙ байт,
-- которого без AES не узнать.
function Stream:skip(ciphertext)
    local n = #ciphertext
    if n == 0 then return end
    if n >= 16 then
        self.r0, self.r1, self.r2, self.r3 = bytes16_to_regs(ciphertext:sub(n - 15, n))
    else
        local tail = regs_to_bytes16(self.r0, self.r1, self.r2, self.r3):sub(n + 1, 16)
        self.r0, self.r1, self.r2, self.r3 = bytes16_to_regs(tail .. ciphertext)
    end
end

function Stream:encrypt(plaintext, yield_fn)
    return self:_process(plaintext, false, yield_fn)
end

function Stream:decrypt(ciphertext, yield_fn)
    return self:_process(ciphertext, true, yield_fn)
end

return { Stream = Stream }
