--[[
Runs the chat window on an emulated OpenComputers machine booted into DwOS, and counts
what it costs.

    lua test_ui_ocvm.lua [path-to-dw-repo]

The emulator (test/ocvm.lua in the DwOS development repo) runs the mod's real machine.lua
and bios under plain Lua, gives it a tier-3 video card with video memory, and -- the part
that matters here -- charges for calls exactly as the mod does, keeping separate counts
for calls that touched the screen and calls that touched a buffer. That makes the claim
in ui.lua's header testable rather than merely plausible: it prints both numbers for the
same 40 chat messages, drawn once through the buffered window and once the naive way
(straight to the card, a call per colour run).

Screen calls are what spend the tick budget the packet loop needs; buffer calls are free.
So the number to watch is `screen`.
]]

local repo = arg[1] or os.getenv("DWREPO") or "C:/Users/User/Desktop/dw"
local here = debug.getinfo(1, "S").source:match("^@(.*)[/\\]") or "."

local function slurp(path)
    local f = io.open(path, "rb")
    if not f then error("cannot read " .. path) end
    local data = f:read("a")
    f:close()
    return (data:gsub("\r\n", "\n"))
end

-- Run from the repo root: ocvm loads the machine, bios and DwOS image by relative path.
local ok_chdir = os.execute and true
package.path = repo .. "/?.lua;" .. package.path
local ocvm = dofile(repo .. "/test/ocvm.lua")

local MACHINE = repo .. "/openos-orig/machine/machine.lua"
local BIOS = repo .. "/openos-orig/machine/bios.lua"
local DIST = repo .. "/dwos/dist"

-- The driver that runs inside the emulated machine. Writes its findings to a file,
-- since the host reads the outcome from the disk afterwards.
local DRIVER = [[
local ui_lib = require("ui")
local ui = ui_lib.new({ title = "ghost . test@galaxy" })
if not ui then io.open("/home/out.txt","w"):write("no gpu\n"):close() return end

local palette = { 0xFF5555, 0x55FF55, 0x55FFFF, 0xFFAA00, 0xAAAAAA, 0xFFFFFF }
for i = 1, 40 do
  -- Four colour runs per line, like a real chat line with a prefix, a nick and text.
  ui:chat({
    { text = "[G] ", color = palette[(i % 6) + 1] },
    { text = "Player" .. i, color = 0x55FFFF },
    { text = ": ", color = 0xAAAAAA },
    { text = "сообщение номер " .. i .. " подлиннее, чтобы проверить перенос строки", color = 0xFFFFFF },
  })
  ui:input("набираю " .. i)
  ui:flush()
end
ui:flush(true)   -- the loop ends here; the rate limit must not eat the last frame
local f = io.open("/home/out.txt", "w")
f:write("done\n")
f:close()
]]

local NAIVE = [[
local term = require("term")
local gpu = term.gpu()
local palette = { 0xFF5555, 0x55FF55, 0x55FFFF, 0xFFAA00, 0xAAAAAA, 0xFFFFFF }
local w, h = gpu.getResolution()
local y = 1
for i = 1, 40 do
  -- The obvious way: a set() per colour run, straight to the card.
  local parts = {
    { "[G] ", palette[(i % 6) + 1] },
    { "Player" .. i, 0x55FFFF },
    { ": ", 0xAAAAAA },
    { "сообщение номер " .. i .. " подлиннее, чтобы проверить перенос строки", 0xFFFFFF },
  }
  if y >= h then gpu.copy(1, 2, w, h - 1, 0, -1); gpu.fill(1, h - 1, w, 1, " "); y = h - 1 end
  local x = 1
  for _, p in ipairs(parts) do
    gpu.setForeground(p[2])
    gpu.set(x, y, p[1])
    x = x + require("unicode").len(p[1])
  end
  y = y + 1
end
local f = io.open("/home/out.txt", "w")
f:write("done\n")
f:close()
]]

local function run(label, driver, extra_files, ram)
    local files = { ["home/drive.lua"] = driver }
    for name, data in pairs(extra_files or {}) do files[name] = data end
    local vm = ocvm.new{
        name = label, machine = MACHINE, bios = BIOS, ram = ram,
        disks = { { dir = DIST, label = "DwOS", kind = "hdd", files = files } },
        boot = 1,
    }
    vm:boot()
    local state = vm:idle(120)
    if state ~= "idle" then
        print(("  %s: machine did not settle (%s) %s"):format(label, tostring(state), tostring(vm.crashed)))
        return nil
    end
    local before = {
        screen = vm.stats.screenCalls, buffer = vm.stats.bufferCalls,
        bitblt = vm.stats.bitblt, ticks = vm.stats.ticks,
    }
    vm:line("/home/drive.lua", 600)
    vm:idle(120)
    local out = vm.disks[1].fs:dump()["home/out.txt"]
    return {
        out = out,
        screen = vm.stats.screenCalls - before.screen,
        buffer = vm.stats.bufferCalls - before.buffer,
        bitblt = vm.stats.bitblt - before.bitblt,
        ticks = vm.stats.ticks - before.ticks,
        finished = out ~= nil,
        crashed = vm.crashed,
        text = vm:text(),
    }
end

local CLIENT_MODULES = {
    "ui.lua", "chat_format.lua", "mc_protocol.lua", "fml.lua", "cfb8.lua", "aes.lua",
    "bit_compat.lua", "rsa.lua", "bignum.lua", "sha1.lua", "rng.lua", "session.lua",
    "modlist.lua", "channels.lua", "hwid.lua",
}

local extra = {}
for _, name in ipairs(CLIENT_MODULES) do
    extra["lib/" .. name] = slurp(here .. "/" .. name)
end

-- Does the whole thing fit on the smallest machine that can run it? A tier-1 RAM stick
-- is 192KB, and this program's two biggest tables (164 mods, 130 channels) exist only
-- to be encoded into two strings -- so the number that matters is how much comes back
-- after they are dropped.
local MEMORY = [[
local computer = require("computer")
-- collectgarbage() is not in the OpenComputers sandbox; freeMemory() is what provokes a
-- collection there, so ask a few times and take the best answer.
local function free()
  local best = 0
  for _ = 1, 4 do
    local n = computer.freeMemory()
    if n > best then best = n end
  end
  return best
end
local start = free()
for _, m in ipairs({ "mc_protocol", "cfb8", "aes", "bit_compat", "rsa", "bignum",
                     "sha1", "rng", "chat_format", "ui" }) do require(m) end
local after_code = free()
local fml = require("fml")
local handshake = fml.new(require("modlist"), function() end, require("channels"))
local after_tables = free()
package.loaded["modlist"], package.loaded["channels"] = nil, nil
local after_release = free()
local f = io.open("/home/out.txt", "w")
f:write(string.format("%d %d %d %d\n", start, after_code, after_tables, after_release))
f:close()
]]

print("40 chat lines, tier-3 card, DwOS:\n")
local buffered = run("buffered", DRIVER, extra)
local naive = run("naive", NAIVE, {})

local function report(label, r)
    if not r then return end
    print(("  %-9s screen=%-6d buffer=%-6d bitblt=%-4d ticks=%-5d finished=%s")
        :format(label, r.screen, r.buffer, r.bitblt, r.ticks, tostring(r.finished)))
    if r.crashed then print("            crashed: " .. tostring(r.crashed)) end
end

report("buffered", buffered)
report("naive", naive)

if buffered and naive and naive.screen > 0 then
    print(("\n  screen calls: %d vs %d -- %.1fx fewer through the buffer")
        :format(buffered.screen, naive.screen, naive.screen / math.max(buffered.screen, 1)))
end

if buffered and buffered.text then
    print("\nwhat the window looks like:")
    local lines = {}
    for line in buffered.text:gmatch("[^\n]*") do lines[#lines + 1] = line end
    for i = 1, #lines do
        if lines[i] and lines[i]:match("%S") then
            print("  | " .. (lines[i]:gsub("%s+$", "")))
        end
    end
end

-- How much RAM does this actually need? Reported per stick size, because "it fits" is
-- the only claim here worth making with a number attached.
for _, ram in ipairs({ 192, 384, 768, 1536 }) do
    local mem = run("mem" .. ram, MEMORY, extra, ram * 1024)
    local label = string.format("\n%d KB of RAM:", ram)
    if mem and mem.out then
        local start, code, tables, released = mem.out:match("(%d+) (%d+) (%d+) (%d+)")
        start, code, tables, released = tonumber(start), tonumber(code), tonumber(tables), tonumber(released)
        print(label)
        print(string.format("  free before the client   %6.1f KB", start / 1024))
        print(string.format("  after loading its code   %6.1f KB   (-%.1f KB)", code / 1024, (start - code) / 1024))
        print(string.format("  with modlist + channels  %6.1f KB   (-%.1f KB)", tables / 1024, (code - tables) / 1024))
        print(string.format("  after dropping them      %6.1f KB   (+%.1f KB back)", released / 1024, (released - tables) / 1024))
    else
        print(label .. " does not fit (the machine could not finish loading)")
        if mem and mem.text then
            for line in mem.text:gmatch("[^\n]+") do
                if line:match("%S") then print("      " .. (line:gsub("%s+$", ""))) end
            end
        end
    end
end

if not buffered or not buffered.finished then
    print("\nFAILED: the window driver did not finish")
    os.exit(1)
end
print("\nok")
