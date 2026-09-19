--[[
Entry point. Put this whole ghost_client_lua/ folder on an OpenComputers disk, then run
`main.lua`. Needs an Internet Card (tier 1 is enough) and, ideally, a Data Card for real
randomness (see rng.lua).

*** Who logs in lives in session.lua, not here -- fill in the access_token there. This
    deliberately never logs in with a username/password itself. ***

Everything runs in ONE coroutine: the packet loop, the keyboard and the redraw. That is
not tidiness, it is a requirement. OpenComputers delivers each key_down event to exactly
one pullSignal caller -- first to ask wins -- so a second listener does not get its own
copy, it *races* the first for keystrokes. A keyboard thread next to the packet loop is
how typed input ends up garbled, split across lines, or silently lost. With one
coroutine there is nothing left to race.

The same yield() is threaded through the login sequence (RSA is slow enough to need its
own yields), the socket reads, and the play loop, so there is exactly one place in the
program that polls the keyboard and exactly one that pushes the screen.
]]
-- Первым делом -- свой каталог в package.path. Без этого клиент не запустится ниоткуда,
-- кроме собственного каталога: в package.path есть "./?.lua", но "." -- это текущий
-- каталог ОБОЛОЧКИ, а не программы. Поставленный в /home/dwclient и запущенный из /home
-- падает на первом же require("connection"): модули лежат рядом с main.lua, а ищут их
-- в /home.
--
-- Путь берётся у процесса, а НЕ через debug.getinfo: в песочнице OpenComputers она
-- отдаёт "=machine" для любого файла, так что узнать себя таким образом невозможно.
-- Проверено на эмуляторе, см. test_install_ocvm.lua.
local function program_dir()
    local ok, process = pcall(require, "process")
    local path = ok and process.info and process.info() and process.info().path
    path = path or os.getenv("_")
    if not path then
        -- Обычный Lua, без OpenComputers: там getinfo как раз работает (тесты).
        local info = debug and debug.getinfo and debug.getinfo(1, "S")
        path = info and info.source and info.source:match("^@(.*)$")
    end
    return path and path:match("^(.*)[/\\][^/\\]*$")
end

local here = program_dir()
if here and here ~= "" then
    package.path = here .. "/?.lua;" .. here .. "/?/init.lua;" .. package.path
end

local computer = require("computer")

local connection = require("connection")
local auth = require("auth")
local chat_format = require("chat_format")
local ui_lib = require("ui")

-- Кто заходит -- в session.lua, это единственный файл под правку руками, и обновление
-- его не трогает. Здесь только куда заходить.
local SESSION = require("session")
local HOST = "proxy-1.metalabsmc.net"
local PORT = 25606 -- Galaxy. (Industrial is 25600 and is a different pack entirely.)

if SESSION.access_token == nil or SESSION.access_token == "" then
    print("session.lua: не вписан access_token -- без него сервер не пустит")
    return
end

local keyboard_ok, keyboard = pcall(require, "keyboard")
local event_ok, event = pcall(require, "event")
local unicode_ok, unicode = pcall(require, "unicode")
local input_enabled = keyboard_ok and event_ok

-- DwOS: ask not to be killed outright by Ctrl+Alt+C. Instead of dying mid-packet with
-- the socket still open, an "interrupted" event arrives like any other and the loop
-- below shuts down in order. Harmless on OpenOS, which simply has no such function.
local process_ok, process = pcall(require, "process")
if process_ok and process.killable then pcall(process.killable, false) end

local ui = ui_lib.new({ title = "ghost . " .. SESSION.username .. "@" .. HOST .. ":" .. PORT })

local function say(text, color)
    if ui then ui:note(text, color) else print(text) end
end

local conn          -- assigned below; handle_key_down sees it through this upvalue
local connected = false -- guards against sending chat before the handshake is finished,
                        -- which would inject a play packet into the login sequence
local input_buf = {}
local last_status = 0

local function status_line()
    local total, free = computer.totalMemory(), computer.freeMemory()
    -- math.floor, а не просто деление: в Lua 5.3 "/" всегда даёт float, а "%d" требует
    -- целого и на дробном падает с "number has no integer representation". Строка
    -- состояния обновляется раз в секунду, так что уронило бы клиент уже в игре.
    return string.format("mem %dK/%dK  %s", math.floor((total - free) / 1024),
        math.floor(total / 1024), connected and "connected" or "connecting")
end

local function handle_key_down(char, code)
    if code == keyboard.keys.enter or code == keyboard.keys.numpadenter then
        local line = table.concat(input_buf)
        input_buf = {}
        if ui then ui:input("") end
        if line ~= "" and connected then
            local ok, err = pcall(conn.send_chat, conn, line)
            if ok then
                say("> " .. line, ui_lib.COLOR_ACCENT)
            else
                say("!! failed to send: " .. tostring(err), ui_lib.COLOR_WARN)
            end
        end
    elseif code == keyboard.keys.back then
        if #input_buf > 0 then
            table.remove(input_buf)
            if ui then ui:input(table.concat(input_buf)) end
        end
    elseif char and char >= 32 then
        local ch
        if unicode_ok then
            local ok, u = pcall(unicode.char, char)
            ch = ok and u or nil
        elseif char < 256 then
            ch = string.char(char)
        end
        if ch then
            input_buf[#input_buf + 1] = ch
            if ui then ui:input(table.concat(input_buf)) end
        end
    end
end

-- Called once per socket read attempt and once per packet. event.pull(0, ...) yields
-- once even with nothing pending -- it does not busy-loop -- and unlike a bare
-- os.sleep(0) it has an event filter, so it cannot swallow a key_down that this
-- program's own handler should have seen.
local stop_requested = false
local function yield()
    if input_enabled then
        local ev, _, char, code = event.pull(0, "key_down")
        if ev == "key_down" then
            pcall(handle_key_down, char, code)
        elseif ev == "interrupted" then
            stop_requested = true
        end
    else
        os.sleep(0)
    end
    if ui then
        local now = computer.uptime()
        if now - last_status >= 1 then
            last_status = now
            ui:status(status_line())
        end
        ui:flush()
    end
end

local function join_server_fn(access_token, uuid_no_dashes, server_hash)
    auth.join_server(access_token, uuid_no_dashes, server_hash)
end

conn = connection.new(HOST, PORT, SESSION, require("modlist"), join_server_fn, yield)

say("connecting to " .. HOST .. ":" .. PORT .. " as " .. SESSION.username .. " ...")
if ui then ui:flush(true) end

local ok, err = pcall(conn.connect, conn)
if not ok then
    say("connect failed: " .. tostring(err), ui_lib.COLOR_WARN)
    if ui then ui:flush(true) end
    return
end
connected = true
say("logged in, waiting for the world", ui_lib.COLOR_OK)

-- Still exposed for another program on the same computer.
_G.ghost_send_chat = function(message)
    conn:send_chat(message)
    say("> " .. message, ui_lib.COLOR_ACCENT)
end

local function on_chat(raw_json)
    if ui then
        ui:chat(chat_format.render_chat_segments(raw_json))
    else
        print(chat_format.render_chat_json(raw_json))
    end
end

local function on_join()
    say("joined the world", ui_lib.COLOR_OK)
end

local reason = conn:run(on_chat, on_join)
connected = false
conn:close()

if ui then
    ui:note("disconnected: " .. tostring(reason), ui_lib.COLOR_WARN)
    ui:status("disconnected -- press any key to exit")
    ui:flush(true)
    if input_enabled and not stop_requested then event.pull(30, "key_down") end
    ui:close()
end
print("disconnected: " .. tostring(reason))
