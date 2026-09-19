--[[
Randomness for the shared secret and RSA PKCS#1 padding. Prefers a real Data Card's
random() (Tier 2 callback, genuinely random) when one is installed; falls back to a
seeded PRNG otherwise (fine for padding bytes, weaker than ideal for the shared secret
itself -- flagged clearly so whoever runs this without a Data Card knows the tradeoff).
]]
local ok, component = pcall(require, "component")
local has_data_card = ok and component.isAvailable and component.isAvailable("data")

local M = { using_data_card = has_data_card }

if has_data_card then
    function M.random_bytes(n)
        return component.data.random(n)
    end
else
    math.randomseed(os.time() + (os.clock() * 1000000))
    function M.random_bytes(n)
        local out = {}
        for i = 1, n do
            out[i] = string.char(math.random(0, 255))
        end
        return table.concat(out)
    end
end

function M.random_byte()
    return string.byte(M.random_bytes(1))
end

return M
