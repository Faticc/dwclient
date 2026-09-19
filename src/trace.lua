--[[
Рассказывает, что происходит прямо сейчас: шаги входа с длительностью, размеры пакетов
и прогресс на долгих операциях.

Нужно оно вот зачем. Тяжёлое здесь считается на самой машине -- RSA при входе и AES
побайтово на каждом пакете, -- и когда клиент "висит", без следа непонятно, ждёт он
сервер, считает или уже потерял соединение. Со следом видно строку и секунды.

Две разные вещи:

  step()     -- отдельная строка в чат: случилось событие. Дёшево, но каждая строка
                занимает место на экране, поэтому только на заметные вехи.
  progress() -- одна строка состояния, переписывается на месте: идёт долгая работа.
                Её зовут из уступки, то есть не чаще раза в пару секунд.

Часы -- computer.uptime(): это игровое время, ровно то, по которому сервер отмеряет
свои таймауты. Под обычным Lua (тесты) берётся os.clock.
]]
local M = {}

local sink_line, sink_status
local clock
local started, last_step

local function now()
    if clock then return clock() end
    local ok, computer = pcall(require, "computer")
    clock = (ok and computer.uptime) or os.clock
    return clock()
end

-- line_fn(текст) -- добавить строку; status_fn(текст) -- переписать строку состояния.
-- Любая может быть nil: тогда след в эту сторону просто молчит.
function M.init(line_fn, status_fn)
    sink_line, sink_status = line_fn, status_fn
    started = now()
    last_step = started
end

function M.enabled()
    return sink_line ~= nil or sink_status ~= nil
end

-- Веха: сколько прошло с прошлой вехи и сколько всего от начала.
function M.step(text)
    if not sink_line then return end
    local t = now()
    local since = t - (last_step or t)
    last_step = t
    if since >= 0.1 then
        sink_line(string.format("%5.1fs +%.1f  %s", t - started, since, text))
    else
        sink_line(string.format("%5.1fs        %s", t - started, text))
    end
end

-- Строка состояния на время долгой работы. done/total, если известны, показываются
-- процентами -- иначе просто текст и сколько уже идёт.
local busy_text, busy_since
function M.busy(text)
    busy_text, busy_since = text, now()
    if sink_status then sink_status(text .. " ...") end
end

function M.progress(done, total)
    if not sink_status or not busy_text then return end
    local elapsed = now() - (busy_since or now())
    if done and total and total > 0 then
        sink_status(string.format("%s: %d%% (%d из %d Б, %.0f с)",
            busy_text, math.floor(done * 100 / total), done, total, elapsed))
    else
        sink_status(string.format("%s: идёт %.0f с", busy_text, elapsed))
    end
end

-- Конец долгой работы: вехой, чтобы осталась в чате, и с реальной длительностью.
function M.done(text)
    if busy_text then
        local elapsed = now() - (busy_since or now())
        if elapsed >= 0.5 then
            M.step(string.format("%s -- %.1f с", text or busy_text, elapsed))
        end
        busy_text, busy_since = nil, nil
    end
    if sink_status then sink_status("") end
end

function M.elapsed()
    return now() - (started or now())
end

return M
