package.path = package.path .. ";./?.lua"
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

local all_ok = true
local function check(name, ok)
    all_ok = all_ok and ok
    print(name .. ": " .. (ok and "OK" or "FAIL"))
end

-- Round-trip small/medium numbers through bytes.
for _, n in ipairs({ 0, 1, 255, 256, 65535, 65536, 123456789, 999999999999 }) do
    local bytes = string.format("%x", n)
    if #bytes % 2 == 1 then bytes = "0" .. bytes end
    local b = bn.from_bytes(hex_to_bytes(bytes))
    local back = to_hex(bn.to_bytes(b))
    local expected = bytes:gsub("^0+(.)", "%1")
    check("roundtrip " .. n, back:gsub("^0+(.)", "%1") == expected)
end

-- add/sub/mul against plain Lua integer math (safe range).
local a = bn.from_int(123456789)
local b = bn.from_int(987654321)
check("add", bn.compare(bn.add(a, b), bn.from_int(123456789 + 987654321)) == 0)
check("sub", bn.compare(bn.sub(b, a), bn.from_int(987654321 - 123456789)) == 0)
check("mul", bn.compare(bn.mul(a, b), bn.from_int(123456789 * 987654321)) == 0)

-- divmod against known values.
local q, r = bn.divmod(bn.from_int(1000000007), bn.from_int(97))
check("divmod q", bn.compare(q, bn.from_int(1000000007 // 97)) == 0)
check("divmod r", bn.compare(r, bn.from_int(1000000007 % 97)) == 0)

-- The real thing: 2048-bit modexp against a Python-computed reference (RSA
-- encryption's shape exactly -- small e=65537, huge modulus).
local n_hex = "f59cde66bacfb3d00b1f9163ce9ff57f43b7a3a69a8dca03580d7b71d8f564135be6128e18c267976142ea7d17be31111a2a73ed562b0f79c37459eef50bea63371ecd7b27cd813047229389571aa8766c307511b2b9437a28df6ec4ce4a2bbdc241330b01a9e71fde8a774bcf36d58b4737819096da1dac72ff5d2a386ecbe06b65a6a48b8148f6b38a088ca65ed389b74d0fb132e706298fadc1a606cb0fb39a1de644815ef6d13b8faa1837f8a88b17fc695a07a0ca6e0822e8f36c031199972a846916419f828b9d2434e465e150bd9c66b3ad3c2d6d1a3d1fa7bc8960a923b8c1e9392456de3eb13b9046685257bdd640fb06671ad11c80317fa3b1799d"
local base_hex = "298218bfaf42e12f3838b3268e944239b02b61c4a3d70628ece66fa2fd5166e6451b4cf36123fdf77656af7229d4beef3eabedcbbaa80dd488bd64072bcfbe01a28defe39bf0027312476f57a5e5a5abaefcfad8efc89849b3aa7efe4458a885ab9099a435a240ae5af305535ec42e0829a3b2e95d65a441d58842dea2bc372f7412b29347294739614ff3d719db3ad0ddd1dfb23b982ef8daf61a26146d3f31fc377a4c4a15544dc5e7ce8a3a578a8ea9488d990bbb259911ce5dd2b45ed1f03139d32c93cd59bf5c941cf0dc98d2c1e2acf72f9e574f7aa0ee89aed453dd324b0dbb418d5288f1142c3fe860e7a113ec1b8ca1f91e1d4c1ff49b7889463e85"
local expected_hex = "5bd75b5b08372a5ebdc3b52b344017c6fa1bbb7102fada82670ca240e380b30e33d0ceaf3724baf6b0109764ac1e986a2302cbe027e8bbc655eb8d57931c6af1d64f5bfeffae9a13f273f8793717a658b5e425da40afdea2187833b72b4c376d6edb5595eca5bd45cb8a35b41ee051d37c353a1bdd8ecfaaefdbdeaed6f8193a91fb8a995e7da35322832ed141ac1ba584f2200f2aa1c5ca7b5ee1ae243edf504620caf467d702bb2c8621a2eb33d959c0ed12066dcc5d750c1dd8a6df51f886c435bba294a58af3b180b3a01beb9dbb3a22510d6e4b656710b2957ba54f841f27df1aa5a78a573b3eb829da6d72fbd50911cf47fe5c8cff299f740db48b6df2"

local n = bn.from_bytes(hex_to_bytes(n_hex))
local base = bn.from_bytes(hex_to_bytes(base_hex))
local e = bn.from_int(65537)

local start = os.clock()
local result = bn.modexp(base, e, n)
local elapsed = os.clock() - start

local got_hex = to_hex(bn.to_bytes(result, #hex_to_bytes(expected_hex)))
check("2048-bit modexp (e=65537)", got_hex == expected_hex)
print(string.format("modexp took %.3f seconds (single AES desktop CPU)", elapsed))

if not all_ok then os.exit(1) end

-- --------------------------------------------------------------------------
-- Приведение по Барретту: тот же остаток, что честное деление
-- --------------------------------------------------------------------------
--
-- Барретт даёт ответ без деления, но оценка частного в нём занижена -- и если поправку
-- сделать неверно, остаток выйдет больше модуля или на модуль меньше нужного. Такая
-- ошибка не заметна на глаз: RSA просто даст неверный шифротекст, а сервер ответит
-- невнятным отказом. Поэтому сверяем с divmod на случайных числах и на краях.
math.randomseed(20260919)
local function rand_bytes(n)
    local t = {}
    for i = 1, n do t[i] = string.char(math.random(0, 255)) end
    return table.concat(t)
end

local barrett_fails = 0
for _, mlen in ipairs({ 4, 16, 64, 128 }) do
    for _ = 1, 20 do
        local mb = rand_bytes(mlen)
        mb = string.char(math.max(1, string.byte(mb, 1))) .. mb:sub(2)
        local m = bn.from_bytes(mb)
        local ctx = bn.barrett(m)
        local x = bn.from_bytes(rand_bytes(math.random(1, 2 * mlen)))
        if bn.compare(x, bn.mul(m, m)) < 0 then
            if bn.compare(bn.barrett_reduce(ctx, x), bn.mod(x, m)) ~= 0 then
                barrett_fails = barrett_fails + 1
            end
        end
    end
end

local m = bn.from_bytes(rand_bytes(64))
local ctx = bn.barrett(m)
local one = bn.from_int(1)
for _, x in ipairs({ bn.from_int(0), bn.sub(m, one), m,
                     bn.sub(bn.mul(m, m), one) }) do
    if bn.compare(bn.barrett_reduce(ctx, x), bn.mod(x, m)) ~= 0 then
        barrett_fails = barrett_fails + 1
    end
end
print("barrett vs divmod: " .. (barrett_fails == 0 and "OK" or (barrett_fails .. " расхождений")))
if barrett_fails > 0 then os.exit(1) end
