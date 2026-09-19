--[[
32-bit bitwise ops for plain Lua (5.1/5.2/5.3+/LuaJIT), auto-detecting the fastest
backend available at load time instead of assuming one:

  1. Lua 5.3/5.4/5.5 native `&`/`|`/`~` operators (fastest -- one VM instruction).
  2. Lua 5.2's built-in `bit32` library.
  3. LuaJIT's `bit` library (values normalized from signed to unsigned first).
  4. Portable byte-level lookup tables (works everywhere, incl. LuaJ, but is the
     slowest option -- see below).

This matters because AES/CFB8 (cfb8.lua/aes.lua) needs one full AES block encryption
*per byte* of network traffic, and that block cipher does on the order of 150 XORs
internally -- so which backend `bxor` resolves to directly multiplies out over every
byte of every packet. Detection happens once at require() time, not per call.

All values are plain Lua numbers treated as unsigned 32-bit integers (0 .. 2^32-1).
Lua numbers are IEEE-754 doubles, which represent integers exactly up to 2^53, so as
long as we never let an intermediate value exceed that, plain +,-,*,% arithmetic is
exact -- this is what the byte-table fallback and the shift/rotate helpers below rely
on, independently of which band/bor/bxor/bnot backend got picked.
]]
local M = {}

local floor = math.floor

-- powers of two 2^0 .. 2^32, used everywhere below to avoid recomputing
local pow2 = {}
do
    local v = 1
    for i = 0, 32 do
        pow2[i] = v
        v = v * 2
    end
end
M.pow2 = pow2

-- Splits a 32-bit unsigned value into 4 bytes, most significant first.
local function to_bytes(x)
    local b3 = x % 256; x = floor(x / 256)
    local b2 = x % 256; x = floor(x / 256)
    local b1 = x % 256; x = floor(x / 256)
    local b0 = x % 256
    return b0, b1, b2, b3
end
M.to_bytes32 = to_bytes

local function from_bytes(b0, b1, b2, b3)
    return ((b0 * 256 + b1) * 256 + b2) * 256 + b3
end
M.from_bytes32 = from_bytes

-- Each candidate below is verified against a known XOR result before being trusted --
-- if a backend exists but doesn't behave as expected (e.g. some exotic integer
-- scaling), detection just falls through to the next candidate instead of silently
-- corrupting every encrypt/decrypt call. The byte-table fallback at the bottom is the
-- only backend that's *unconditionally* correct, everything above it is opportunistic.
local function detect_native()
    -- Lua 5.3/5.4/5.5 native operators. Written inside load() so this is only ever
    -- *parsed* if load() itself exists to parse it -- on Lua 5.1/5.2, which don't have
    -- this operator syntax at all, load() simply returns nil+error instead of the
    -- whole file failing to load. Shifts are included here too (same dialect that has
    -- `&`/`|`/`~` also has `<<`/`>>`) -- see the note below M.rshift32/M.lshift32 for
    -- why deriving those from native shifts instead of floor/pow2 division matters.
    -- to_bytes32/from_bytes32/rotl32 are generated here too, as single self-contained
    -- closures that do all their shifting/masking inline with native operators --
    -- NOT composed by calling the band/bor/lshift/rshift closures above multiple
    -- times each. Measured with lupa (real Lua 5.5): composing to_bytes32 from
    -- separate nband/nrshift calls (5 Lua function calls per to_bytes32) was actually
    -- *slower* than the original floor()/modulo version (3 floor() calls) it was
    -- meant to replace -- Lua-to-Lua call overhead dominates over the arithmetic
    -- being replaced. Inlining everything into one closure (1 call, all bitwise ops
    -- as raw VM instructions inside) is what actually wins instead.
    local ok, band, bor, bxor, bnot, lshift, rshift, rotl, to_bytes32, from_bytes32 = pcall(function()
        local chunk = load([[
            local function to_bytes32(x)
                return (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff
            end
            local function from_bytes32(b0, b1, b2, b3)
                return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff
            end
            local function rotl(x, n)
                n = n % 32
                if n == 0 then return x & 0xffffffff end
                return ((x << n) | (x >> (32 - n))) & 0xffffffff
            end
            return
                function(a, b) return (a & b) & 0xffffffff end,
                function(a, b) return (a | b) & 0xffffffff end,
                function(a, b) return (a ~ b) & 0xffffffff end,
                function(a) return (~a) & 0xffffffff end,
                function(a, n) return (a << n) & 0xffffffff end,
                function(a, n) return (a >> n) & 0xffffffff end,
                rotl, to_bytes32, from_bytes32
        ]])
        return chunk()
    end)
    if ok and bxor(0xff00ff00, 0x0f0f0f0f) == 0xf00ff00f
        and lshift(0x000000ff, 24) == 0xff000000 and rshift(0xff00ff00, 8) == 0x00ff00ff then
        return band, bor, bxor, bnot, lshift, rshift, "native operators", rotl, to_bytes32, from_bytes32
    end

    -- Lua 5.2's built-in bit32 library.
    if bit32 and bit32.bxor(0xff00ff00, 0x0f0f0f0f) == 0xf00ff00f then
        return bit32.band, bit32.bor, bit32.bxor, bit32.bnot, bit32.lshift, bit32.rshift, "bit32"
    end

    -- LuaJIT's `bit` library treats values as signed 32-bit ints -- normalize back to
    -- our unsigned 0..2^32-1 convention before handing the functions out.
    local req_ok, bitlib = pcall(require, "bit")
    if req_ok and bitlib then
        local function u32(v) if v < 0 then v = v + 4294967296 end return v end
        local nband = function(a, b) return u32(bitlib.band(a, b)) end
        local nbor = function(a, b) return u32(bitlib.bor(a, b)) end
        local nbxor = function(a, b) return u32(bitlib.bxor(a, b)) end
        local nbnot = function(a) return u32(bitlib.bnot(a)) end
        -- LuaJIT's lshift/rshift already return unsigned-looking 32-bit results (the
        -- top bit just prints as negative if you tostring() it, but bitwise-compares
        -- and further bit ops on it are fine) -- but normalize explicitly anyway so
        -- callers can freely mix these with +,-,* like the rest of this module.
        local nlshift = function(a, n) return u32(bitlib.lshift(a, n)) end
        local nrshift = function(a, n) return u32(bitlib.rshift(a, n)) end
        if nbxor(0xff00ff00, 0x0f0f0f0f) == 0xf00ff00f then
            return nband, nbor, nbxor, nbnot, nlshift, nrshift, "LuaJIT bit"
        end
    end

    return nil
end

local nband, nbor, nbxor, nbnot, nlshift, nrshift, backend_name, nrotl, nto_bytes32, nfrom_bytes32 = detect_native()
M.backend = backend_name or "byte-table" -- exposed for diagnostics/tests, not required for use

if nband then
    M.band, M.bor, M.bxor, M.bnot = nband, nbor, nbxor, nbnot
    M.lshift32 = nlshift
    M.rshift32 = nrshift

    -- Those are called *very* often on this codebase's hot path -- to_bytes32 alone
    -- runs 4x per AES round, 9-10 rounds per block, once per byte of network traffic
    -- (see aes.lua) -- so which implementation these resolve to matters. Only the
    -- "native operators" backend (Lua 5.3+) gets the fully-inlined single-closure
    -- versions built inside detect_native() above; bit32/LuaJIT compose them from
    -- the primitives above instead (untested against the floor-based version this
    -- replaces -- couldn't be exercised via lupa, see project-lua-bit-compat-
    -- optimization memory -- but at worst matches its call count, band/bor/lshift/
    -- rshift there are C functions, not Lua closures, so the "extra Lua call is
    -- slower" trap measured for the native-operator path doesn't apply the same way).
    if nrotl then
        M.rotl32, M.to_bytes32, M.from_bytes32 = nrotl, nto_bytes32, nfrom_bytes32
    else
        function M.rotl32(x, n)
            n = n % 32
            if n == 0 then return nband(x, 0xffffffff) end
            return nbor(nlshift(x, n), nrshift(x, 32 - n))
        end

        function M.to_bytes32(x)
            return nrshift(x, 24), nband(nrshift(x, 16), 0xff), nband(nrshift(x, 8), 0xff), nband(x, 0xff)
        end

        function M.from_bytes32(b0, b1, b2, b3)
            return nbor(nbor(nlshift(b0, 24), nlshift(b1, 16)), nbor(nlshift(b2, 8), b3))
        end
    end
else
    -- Byte-level AND/OR/XOR tables, built once. 256x256 entries each; trivial
    -- arithmetic, takes well under a second even in a slow interpreter.
    local BAND, BOR, BXOR = {}, {}, {}
    for a = 0, 255 do
        BAND[a], BOR[a], BXOR[a] = {}, {}, {}
        for b = 0, 255 do
            local band_ab, bor_ab, bxor_ab = 0, 0, 0
            local aa, bb, bit = a, b, 1
            for _ = 1, 8 do
                local abit = aa % 2
                local bbit = bb % 2
                if abit == 1 and bbit == 1 then band_ab = band_ab + bit end
                if abit == 1 or bbit == 1 then bor_ab = bor_ab + bit end
                if abit ~= bbit then bxor_ab = bxor_ab + bit end
                aa = floor(aa / 2)
                bb = floor(bb / 2)
                bit = bit * 2
            end
            BAND[a][b] = band_ab
            BOR[a][b] = bor_ab
            BXOR[a][b] = bxor_ab
        end
    end

    local function byteop(tbl, x, y)
        local xa, xb, xc, xd = to_bytes(x)
        local ya, yb, yc, yd = to_bytes(y)
        return from_bytes(tbl[xa][ya], tbl[xb][yb], tbl[xc][yc], tbl[xd][yd])
    end

    function M.band(x, y) return byteop(BAND, x, y) end
    function M.bor(x, y) return byteop(BOR, x, y) end
    function M.bxor(x, y) return byteop(BXOR, x, y) end

    function M.bnot(x)
        return 4294967295 - x -- 2^32 - 1 - x, i.e. flip every bit of a 32-bit value
    end
end

-- Logical left/right shift and rotate-left, plus to_bytes32/from_bytes32 (only
-- defined here -- i.e. NOT overwriting the native-shift-based versions set above --
-- when no native shift backend was found, so this is the byte-table-fallback's
-- shift/rotate/pack implementation).
if not M.lshift32 then
    -- Pure arithmetic, independent of the band/bor/bxor backend picked above.
    function M.lshift32(x, n)
        if n <= 0 then return x % pow2[32] end
        if n >= 32 then return 0 end
        return (x % pow2[32 - n]) * pow2[n]
    end

    function M.rshift32(x, n)
        if n <= 0 then return x % pow2[32] end
        if n >= 32 then return 0 end
        return floor(x / pow2[n])
    end

    -- Written to avoid ever forming x * 2^n directly (which would overflow past
    -- 2^53 for large x and n) -- instead splits x into the part that stays (low
    -- 32-n bits) and the part that wraps around (top n bits) first.
    function M.rotl32(x, n)
        n = n % 32
        if n == 0 then return x % pow2[32] end
        local high = floor(x / pow2[32 - n])       -- top n bits -> becomes the low n bits
        local low = x - high * pow2[32 - n]         -- bottom (32-n) bits -> shift up by n
        return low * pow2[n] + high
    end
end

function M.add32(...)
    local s = 0
    for _, v in ipairs({...}) do
        s = s + v
    end
    return s % pow2[32]
end

return M
