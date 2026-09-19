--[[
Ставит собранный клиент в /home/dwclient на эмулированной машине DwOS и запускает его
оттуда же, откуда его запустит человек -- из /home, а не из каталога программы.

    lua test_install_ocvm.lua [путь-к-репозиторию-dw]

Проверяется ровно одно, зато то, на чём клиент уже один раз упал живьём: что require
находит соседние модули. Каталог программы не совпадает с текущим каталогом оболочки, а
в package.path стоит "./?.lua" -- то есть каталог оболочки. Пока main.lua сам не добавит
свой каталог в путь, /home/dwclient/main.lua из /home не запускается вовсе.

Дальше первого require дело не идёт по честной причине: интернет-карты у эмулятора нет,
и клиент упирается в неё. Это и есть признак успеха -- значит все модули загрузились.
]]

local repo = arg[1] or os.getenv("DWREPO") or "C:/Users/User/Desktop/dw"
local here = debug.getinfo(1, "S").source:match("^@(.*)[/\\]") or "."
local dist = here:gsub("[/\\]src$", "") .. "/dist"

local function slurp(path)
    local f = io.open(path, "rb")
    if not f then error("не читается " .. path) end
    local data = f:read("a")
    f:close()
    return (data:gsub("\r\n", "\n"))
end

local ocvm = dofile(repo .. "/test/ocvm.lua")

-- Всё из dist/ кладётся в /home/dwclient, как это сделал бы install.lua.
local files = {}
local names = {
    "main.lua", "session.lua", "hwid.lua", "auth.lua", "connection.lua", "fml.lua",
    "ui.lua", "mc_protocol.lua", "cfb8.lua", "aes.lua", "bit_compat.lua", "rsa.lua",
    "bignum.lua", "sha1.lua", "rng.lua", "chat_format.lua", "cluster_client.lua",
    "modlist.lua", "channels.lua",
}
for _, name in ipairs(names) do
    files["home/dwclient/" .. name] = slurp(dist .. "/" .. name)
end
-- Токен нужен только чтобы пройти проверку в начале main.lua: до сети дело не дойдёт.
files["home/dwclient/session.lua"] =
    'return{username="TestBot",uuid="00000000-0000-0000-0000-000000000000",access_token="x"}\n'

local vm = ocvm.new{
    name = "install", machine = repo .. "/openos-orig/machine/machine.lua",
    bios = repo .. "/openos-orig/machine/bios.lua",
    disks = { { dir = repo .. "/dwos/dist", label = "DwOS", kind = "hdd", files = files } },
    boot = 1,
}
vm:boot()
if vm:idle(120) ~= "idle" then
    print("машина не загрузилась: " .. tostring(vm.crashed))
    os.exit(1)
end

-- Именно так, как в жизни: текущий каталог /home, программа в /home/dwclient.
vm:line("cd /home; clear")
vm:idle(30)
vm:line("/home/dwclient/main.lua", 600)
vm:idle(120)

local screen = vm:text()
print("экран после запуска:")
for line in screen:gmatch("[^\n]+") do
    if line:match("%S") then print("  | " .. (line:gsub("%s+$", ""))) end
end

local bad = screen:match("module '([%w_]+)' not found")
if bad then
    print("\nFAILED: require не нашёл модуль '" .. bad .. "' -- каталог программы не в package.path")
    os.exit(1)
end
if screen:match("attempt to") or screen:match("stack traceback") then
    print("\nFAILED: клиент упал")
    os.exit(1)
end
print("\nok: все модули загрузились, дальше упёрлись в отсутствие интернет-карты")
