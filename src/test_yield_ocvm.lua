--[[
Проверяет, что клиент действительно уступает управление, а не делает вид.

    lua test_yield_ocvm.lua [путь-к-репозиторию-dw]

История, ради которой тест написан. Расшифровка идёт байт за байтом, на каждый байт --
полный блок AES, и реестр сервера приходит одним куском в 45 КБ. Чтобы сторож
OpenComputers не убил программу, cfb8 зовёт yield_fn каждые 64 байта. Но сама уступка
была написана как event.pull(0, "key_down") -- а она, как и os.sleep(0), внутри считает
дедлайн "сейчас + 0", на первой же проверке видит, что ждать нечего, и выходит, ни разу
не позвав computer.pullSignal. Уступки не было вовсе, и клиент падал в игре с "too long
without yielding".

Сам сторож тут не проверить: время у эмулятора виртуальное и идёт тиками, так что
занятый цикл на нём ничего не "просрочивает". Зато эмулятор считает каждый настоящий
уход в pullSignal -- а это и есть то, что нужно знать: уступка либо происходит, либо
нет. Тест зовёт каждый способ по три десятка раз и смотрит на счётчик, сравнивая
с холостым прогоном: оболочка уступает и сама, поэтому важна разница, а не число.
]]

local repo = arg[1] or os.getenv("DWREPO") or "C:/Users/User/Desktop/dw"

local ocvm = dofile(repo .. "/test/ocvm.lua")

local N = 30

local DRIVER = [[
local computer = require("computer")
local yield = %s
for _ = 1, %d do yield() end
local f = io.open("/home/out.txt", "w")
f:write("done")
f:close()
]]

local WAYS = {
    { 'ничего (базовая линия)', 'function() end',                                      false },
    { 'os.sleep(0)',            'function() os.sleep(0) end',                          false },
    { 'event.pull(0, "...")',   'function() require("event").pull(0, "key_down") end',  false },
    { 'computer.pullSignal(0)', 'function() computer.pullSignal(0) end',                true  },
}

-- Оболочка уступает и сама по себе, поэтому важно не абсолютное число, а насколько
-- прогон обогнал холостой.
local baseline

local failures = 0
for _, way in ipairs(WAYS) do
    local label, expr, should_yield = way[1], way[2], way[3]
    local vm = ocvm.new{
        name = "yield", machine = repo .. "/openos-orig/machine/machine.lua",
        bios = repo .. "/openos-orig/machine/bios.lua",
        disks = { { dir = repo .. "/dwos/dist", label = "DwOS", kind = "hdd",
                    files = { ["home/drive.lua"] = DRIVER:format(expr, N) } } },
        boot = 1,
    }
    vm:boot()
    if vm:idle(120) ~= "idle" then
        print("  машина не загрузилась: " .. tostring(vm.crashed))
        os.exit(1)
    end

    local before = vm.stats.yields
    vm:line("/home/drive.lua", 20000)
    vm:idle(2000)
    local yields = vm.stats.yields - before
    local finished = vm.disks[1].fs:dump()["home/out.txt"] ~= nil

    if baseline == nil then baseline = yields end
    local yielded = yields >= baseline + N * 0.8
    if finished and yielded == should_yield then
        print(string.format("  ok   %-22s %d уступок на %d вызовов", label, yields, N))
        if not should_yield and baseline ~= yields then
            print("       (столько же, сколько вхолостую -- значит не уступает)")
        end
    else
        print(string.format("  FAIL %-22s %d уступок на %d вызовов, дошло=%s (ожидалось %s)",
            label, yields, N, tostring(finished), should_yield and "что уступает" or "что нет"))
        failures = failures + 1
    end
end

if failures > 0 then
    print("\n" .. failures .. " FAILED")
    os.exit(1)
end
print("\nok: уступает только computer.pullSignal(0), её клиент и зовёт")
