package.path = package.path .. ";./?.lua"
local sha1 = require("sha1")

local cases = {
    { input = "", expected = "da39a3ee5e6b4b0d3255bfef95601890afd80709" },
    { input = "abc", expected = "a9993e364706816aba3e25717850c26c9cd0d89d" },
    { input = "Notch", expected = "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48" },
    { input = "The quick brown fox jumps over the lazy dog", expected = "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12" },
}

local all_ok = true
for _, c in ipairs(cases) do
    local got = sha1.to_hex(sha1.hash(c.input))
    local ok = got == c.expected
    all_ok = all_ok and ok
    print(string.format("%-50s got=%s expected=%s %s", "[" .. c.input .. "]", got, c.expected, ok and "OK" or "FAIL"))
end

os.exit(all_ok and 0 or 1)
