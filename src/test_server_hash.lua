package.path = package.path .. ";./?.lua"

-- connection.lua requires OC-only modules (component, internet) at load time, which
-- don't exist outside the game -- stub them out just enough for this file to load, so
-- we can test server_hash_hex() in isolation on a desktop Lua.
package.loaded["component"] = setmetatable({}, { __index = function() return function() end end })
package.loaded["internet"] = { open = function() end }

local connection = require("connection")

local cases = {
    { input = "Notch", expected = "4ed1f46bbe04bc756bcb17c0c7ce3e4632f06a48" },
    { input = "jeb_", expected = "-7c9d5b0044c130109a5d7b5fb5c317c02b4e28c1" },
    { input = "simon", expected = "88e16a1019277b15d58faf0541e11910eb756f6" },
}

local all_ok = true
for _, c in ipairs(cases) do
    -- server_hash_hex(server_id, shared_secret, public_key_der) -- feed the whole
    -- test string as server_id with empty secret/key to reproduce the classic
    -- sha1(name)-only reference vectors.
    local got = connection.server_hash_hex(c.input, "", "")
    local ok = got == c.expected
    all_ok = all_ok and ok
    print(string.format("%-8s got=%-42s expected=%-42s %s", c.input, got, c.expected, ok and "OK" or "FAIL"))
end

os.exit(all_ok and 0 or 1)
