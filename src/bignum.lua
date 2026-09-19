--[[
Minimal unsigned bignum: enough for RSA *encryption* (modular exponentiation with a
small public exponent, e=65537 in practice -- only 17 bits, so modexp needs just ~17
modular multiplications no matter how big the modulus is; this is why RSA encryption
is cheap even in a slow interpreter, unlike decryption/signing with a huge exponent).

Limbs are base 2^16 (BASE), least-significant limb first, plain Lua array (1-indexed).
16-bit limbs keep every intermediate sum in multiply() comfortably under 2^53 (exact
double range) without needing per-term carry propagation: (2^16-1)^2 summed over up to
~256 terms is still only ~2^39.

divmod uses simple binary (shift-and-subtract) long division -- O(bits) rather than
O(limbs) per division, but simple to get right, and RSA-encrypt only ever needs on the
order of 2*bit_length(e) of these (~34 for e=65537), which is fast enough in practice.
]]
local M = {}

local BASE = 65536
local floor = math.floor

-- Plain explicit-loop array copy. NOTE: do NOT write this as
-- `{ table.unpack and table.unpack(a) or unpack(a) }` -- Lua's `and/or` truncates a
-- multi-return expression to its first value when it isn't the last item in an
-- expression list, so that idiom silently copies only a[1].
local function copy(a)
    local out = {}
    for i = 1, #a do out[i] = a[i] end
    return out
end

local function normalize(a)
    local n = #a
    while n > 1 and a[n] == 0 do
        n = n - 1
    end
    local out = {}
    for i = 1, n do out[i] = a[i] end
    return out
end
M.normalize = normalize

function M.from_bytes(bytes)
    -- Big-endian input -> little-endian-limb bignum.
    local limbs = { 0 }
    for i = 1, #bytes do
        -- limbs = limbs * 256 + byte
        local carry = string.byte(bytes, i)
        for j = 1, #limbs do
            local v = limbs[j] * 256 + carry
            limbs[j] = v % BASE
            carry = floor(v / BASE)
        end
        while carry > 0 do
            limbs[#limbs + 1] = carry % BASE
            carry = floor(carry / BASE)
        end
    end
    return normalize(limbs)
end

function M.from_int(n)
    local limbs = {}
    if n == 0 then return { 0 } end
    while n > 0 do
        limbs[#limbs + 1] = n % BASE
        n = floor(n / BASE)
    end
    return limbs
end

function M.to_bytes(a, min_len)
    a = normalize(a)
    local out = {}
    local limbs = copy(a)
    -- Repeatedly divide the whole bignum by 256 to peel off bytes, least significant
    -- first; reverse at the end. Simple and only runs len(bytes) ~ len(limbs)*2 times.
    while not (#limbs == 1 and limbs[1] == 0) do
        local rem = 0
        for i = #limbs, 1, -1 do
            local cur = rem * BASE + limbs[i]
            limbs[i] = floor(cur / 256)
            rem = cur % 256
        end
        limbs = normalize(limbs)
        out[#out + 1] = rem
    end
    while #out < (min_len or 0) do
        out[#out + 1] = 0
    end
    local chars = {}
    for i = #out, 1, -1 do
        chars[#chars + 1] = string.char(out[i])
    end
    if #chars == 0 then chars = { string.char(0) } end
    return table.concat(chars)
end

function M.compare(a, b)
    a, b = normalize(a), normalize(b)
    if #a ~= #b then return (#a < #b) and -1 or 1 end
    for i = #a, 1, -1 do
        if a[i] ~= b[i] then return (a[i] < b[i]) and -1 or 1 end
    end
    return 0
end

function M.is_zero(a)
    a = normalize(a)
    return #a == 1 and a[1] == 0
end

-- a + b
function M.add(a, b)
    local out = {}
    local carry = 0
    local n = math.max(#a, #b)
    for i = 1, n do
        local v = (a[i] or 0) + (b[i] or 0) + carry
        out[i] = v % BASE
        carry = floor(v / BASE)
    end
    if carry > 0 then out[n + 1] = carry end
    return normalize(out)
end

-- a - b, requires a >= b
function M.sub(a, b)
    local out = {}
    local borrow = 0
    for i = 1, #a do
        local v = a[i] - (b[i] or 0) - borrow
        if v < 0 then
            v = v + BASE
            borrow = 1
        else
            borrow = 0
        end
        out[i] = v
    end
    return normalize(out)
end

-- Shift left by exactly 1 bit.
local function shl1(a)
    local out = {}
    local carry = 0
    for i = 1, #a do
        local v = a[i] * 2 + carry
        out[i] = v % BASE
        carry = floor(v / BASE)
    end
    if carry > 0 then out[#a + 1] = carry end
    return out
end
M.shl1 = shl1

-- Shift right by exactly 1 bit.
local function shr1(a)
    local out = {}
    local carry = 0
    for i = #a, 1, -1 do
        local v = carry * BASE + a[i]
        out[i] = floor(v / 2)
        carry = v % 2
    end
    return normalize(out)
end
M.shr1 = shr1

local function is_odd(a)
    return a[1] % 2 == 1
end

-- Schoolbook multiply. Every accumulated position is summed fully before its single
-- carry-propagation pass at the very end, so intermediate sums stay comfortably under
-- 2^53 (see module comment).
function M.mul(a, b)
    local out = {}
    for i = 1, #a + #b do out[i] = 0 end
    for i = 1, #a do
        local ai = a[i]
        if ai ~= 0 then
            for j = 1, #b do
                out[i + j - 1] = out[i + j - 1] + ai * b[j]
            end
        end
    end
    local carry = 0
    for i = 1, #out do
        local v = out[i] + carry
        out[i] = v % BASE
        carry = floor(v / BASE)
    end
    while carry > 0 do
        out[#out + 1] = carry % BASE
        carry = floor(carry / BASE)
    end
    return normalize(out)
end

-- Binary long division: returns quotient, remainder such that a == q*b + r.
-- yield_fn, if given, is called periodically (see modexp) to let a caller keep an
-- OpenComputers program under its per-tick CPU budget.
function M.divmod(a, b, yield_fn)
    assert(not M.is_zero(b), "division by zero")
    a = normalize(a)
    if M.compare(a, b) < 0 then
        return M.from_int(0), a
    end

    -- Find how many bits `a` has by shifting `b` left until it's just <= a.
    local shifted = copy(b)
    local shift_count = 0
    while M.compare(shl1(shifted), a) <= 0 do
        shifted = shl1(shifted)
        shift_count = shift_count + 1
    end

    local remainder = a
    local quotient = M.from_int(0)
    for i = shift_count, 0, -1 do
        quotient = shl1(quotient)
        if M.compare(remainder, shifted) >= 0 then
            remainder = M.sub(remainder, shifted)
            quotient[1] = quotient[1] + 1
        end
        shifted = shr1(shifted)
        if yield_fn and i % 64 == 0 then yield_fn() end
    end
    return normalize(quotient), normalize(remainder)
end

function M.mod(a, m, yield_fn)
    local _, r = M.divmod(a, m, yield_fn)
    return r
end

-- --------------------------------------------------------------------------
-- Приведение по Барретту: остаток без деления
-- --------------------------------------------------------------------------
--
-- divmod выше -- двоичное деление сдвигом и вычитанием: O(бит) проходов, на каждом
-- работа со всеми разрядами. Для модуля в 1024 бита это порядка двух тысяч проходов по
-- 64 разрядам, тогда как умножение тех же чисел -- 64*64 = 4096 действий. То есть одно
-- приведение стоит примерно как тридцать умножений, а в modexp их восемнадцать:
-- деление и было всем временем RSA.
--
-- Барретт заменяет деление двумя умножениями. Один раз считается mu = b^(2k) / m (вот
-- это деление дорогое, но оно единственное на весь modexp), после чего остаток берётся
-- так:
--
--     q = ((x / b^(k-1)) * mu) / b^(k+1)       -- оценка частного
--     r = (x mod b^(k+1)) - (q*m mod b^(k+1))  -- и поправка, если промахнулись
--
-- Деление и остаток по степеням основания -- это просто отбрасывание разрядов, то есть
-- бесплатно. Оценка q занижена не более чем на 2, поэтому поправка -- максимум два
-- вычитания.
--
-- Требование: x < b^(2k). В modexp x всегда произведение двух чисел меньше m, значит
-- x < m^2 <= b^(2k). Проверка ниже не даёт применить приведение вне этого условия:
-- молча вернуть неверный остаток было бы хуже, чем упасть.

-- Отбросить младшие n разрядов (деление на b^n).
local function shift_down(a, n)
    if n <= 0 then return copy(a) end
    local out = {}
    for i = n + 1, #a do out[i - n] = a[i] end
    return normalize(out)
end

-- Оставить только младшие n разрядов (остаток от деления на b^n).
local function truncate(a, n)
    local out = {}
    for i = 1, n do out[i] = a[i] or 0 end
    return normalize(out)
end

-- Контекст для многократного приведения по одному модулю.
function M.barrett(m, yield_fn)
    m = normalize(m)
    local k = #m
    local b2k = {}
    for i = 1, 2 * k do b2k[i] = 0 end
    b2k[2 * k + 1] = 1
    local mu = M.divmod(b2k, m, yield_fn)
    return { m = m, k = k, mu = mu }
end

function M.barrett_reduce(ctx, x)
    local m, k, mu = ctx.m, ctx.k, ctx.mu
    x = normalize(x)
    assert(#x <= 2 * k, "barrett: число больше b^(2k), приведение неприменимо")

    local q = shift_down(M.mul(shift_down(x, k - 1), mu), k + 1)
    local r = truncate(x, k + 1)
    local qm = truncate(M.mul(q, m), k + 1)

    if M.compare(r, qm) < 0 then
        -- r - qm ушло бы в минус: занимаем b^(k+1). Это и есть та самая арифметика по
        -- модулю b^(k+1), в которой считается разность.
        local borrow = {}
        for i = 1, k + 1 do borrow[i] = 0 end
        borrow[k + 2] = 1
        r = M.sub(M.add(r, borrow), qm)
    else
        r = M.sub(r, qm)
    end

    while M.compare(r, m) >= 0 do
        r = M.sub(r, m)
    end
    return r
end

-- base^exp mod m, square-and-multiply from the most significant exponent bit down.
--
-- Приведение -- по Барретту: одно дорогое деление на подготовку контекста вместо
-- одного на каждое из ~18 умножений.
function M.modexp(base, exp, m, yield_fn)
    local ctx = M.barrett(m, yield_fn)
    base = M.barrett_reduce(ctx, base)
    local result = M.from_int(1)
    exp = normalize(exp)

    -- collect exponent bits, most significant first
    local bits = {}
    local e = copy(exp)
    while not M.is_zero(e) do
        bits[#bits + 1] = e[1] % 2
        e = shr1(e)
    end
    -- bits is currently least-significant first; walk it in reverse (MSB first)
    for i = #bits, 1, -1 do
        result = M.barrett_reduce(ctx, M.mul(result, result))
        if bits[i] == 1 then
            result = M.barrett_reduce(ctx, M.mul(result, base))
        end
        if yield_fn then yield_fn() end
    end
    return result
end

return M
