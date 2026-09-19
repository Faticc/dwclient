--[[
Chat window: a title bar, a colour scrollback, a status line and an input line.

Built for how OpenComputers charges for graphics, which is the whole reason this is not
just print(). A direct call to the video card costs a slice of the tick budget -- on a
tier-3 card `set` is 1/256 of a tick, `fill` 1/128, `copy` 1/64 -- while calls into a
video-memory buffer are free, and only pushing a dirty buffer to the screen costs
anything (2.0 * w*h/8000, so a full screen is about a whole tick). A single coloured
chat line is easily a dozen `set` calls, one per colour run; doing those straight to the
screen is how a busy chat eats the tick budget the packet loop needs.

So: everything is drawn into a DwOS `gfx.surface`, the screen is updated at most once per
game tick, and only when something actually changed. DwOS's gfx then decides for itself
whether to replay the few operations directly (cheaper for a small change) or do one
bitblt. New chat scrolls with a single `copy` of the whole scrollback area rather than
redrawing every line.

Measured, not assumed: test_ui_ocvm.lua runs 40 coloured chat lines on an emulated
tier-3 machine and counts the calls the mod would charge for. Buffered: 362 screen
calls. The same lines drawn straight to the card: 671. Both numbers include the input
line being retyped on every message, which is the worst case for the buffered version.
Note that the rate limit in flush() is doing most of that work -- an earlier version
presented after every message and came out at 996, i.e. WORSE than naive drawing. A
buffer you push too often is not an optimisation.

Degrades in two steps: with no gfx library it drives the GPU directly with the same
calls; with no GPU at all every method becomes a no-op and main.lua falls back to print.
]]
local M = {}

local gfx_ok, gfx = pcall(require, "gfx")
local unicode_ok, unicode = pcall(require, "unicode")

local ulen = unicode_ok and unicode.len or function(s) return #s end
local usub = unicode_ok and unicode.sub or string.sub

local COLOR_BG = 0x000000
local COLOR_BAR = 0x2D2D2D
local COLOR_BAR_TEXT = 0xFFFFFF
local COLOR_ACCENT = 0x55FFFF
local COLOR_DIM = 0xAAAAAA
local COLOR_TEXT = 0xCCCCCC
local COLOR_OK = 0x55FF55
local COLOR_WARN = 0xFFAA00

local computer = require("computer")

local Ui = {}
Ui.__index = Ui

-- A plain-GPU stand-in for gfx.surface, so the drawing code below has exactly one
-- shape to talk to. Every call goes straight to the card (and costs budget); present()
-- has nothing to do because there is no buffer to push.
local function direct_surface(gpu)
    local w, h = gpu.getResolution()
    local fg, bg
    return {
        w = w, h = h,
        set = function(self, x, y, s, f, b)
            f, b = f or COLOR_TEXT, b or COLOR_BG
            if f ~= fg then gpu.setForeground(f); fg = f end
            if b ~= bg then gpu.setBackground(b); bg = b end
            gpu.set(x, y, s)
        end,
        fill = function(self, x, y, fw, fh, ch, f, b)
            f, b = f or COLOR_TEXT, b or COLOR_BG
            if f ~= fg then gpu.setForeground(f); fg = f end
            if b ~= bg then gpu.setBackground(b); bg = b end
            gpu.fill(x, y, fw, fh, ch or " ")
        end,
        copy = function(self, x, y, cw, ch, tx, ty) gpu.copy(x, y, cw, ch, tx, ty) end,
        present = function() end,
        close = function() end,
    }
end

-- opts.title is shown in the bar; opts.scrollback is how many past lines to keep for a
-- redraw (only used on resize/redraw, so a modest number is plenty).
function M.new(opts)
    opts = opts or {}
    local term_ok, term = pcall(require, "term")
    if not term_ok then return nil end
    local gpu_ok, gpu = pcall(function() return term.gpu() end)
    if not gpu_ok or not gpu then return nil end

    local surface
    if gfx_ok then
        local ok, s = pcall(gfx.surface, gpu)
        surface = ok and s or nil
    end
    if not surface then surface = direct_surface(gpu) end

    local self = setmetatable({
        gpu = gpu,
        s = surface,
        w = surface.w,
        h = surface.h,
        title = opts.title or "ghost",
        status_text = "",
        input_text = "",
        dirty = true,
        clock = computer.uptime,
        last_present = 0,
        input_drawn = 0,
        -- Scrollback area runs from row 2 to h-2: row 1 is the title bar, h-1 the
        -- status line, h the input line.
        top = 2,
        bottom = surface.h - 2,
    }, Ui)
    self.rows = self.bottom - self.top + 1
    self.used = 0 -- rows of the scrollback filled so far, before it starts scrolling

    self.s:fill(1, 1, self.w, self.h, " ", COLOR_TEXT, COLOR_BG)
    self:_draw_bar()
    self:_draw_status()
    self:_draw_input()
    self:flush(true)
    return self
end

function Ui:_draw_bar()
    self.s:fill(1, 1, self.w, 1, " ", COLOR_BAR_TEXT, COLOR_BAR)
    self.s:set(2, 1, usub(self.title, 1, self.w - 2), COLOR_BAR_TEXT, COLOR_BAR)
    self.dirty = true
end

function Ui:_draw_status()
    local y = self.h - 1
    self.s:fill(1, y, self.w, 1, " ", COLOR_DIM, COLOR_BG)
    if self.status_text ~= "" then
        self.s:set(2, y, usub(self.status_text, 1, self.w - 2), COLOR_DIM, COLOR_BG)
    end
    self.dirty = true
end

function Ui:_draw_input()
    local y = self.h
    -- Show the tail when the line is longer than the screen, the way a real prompt does.
    local room = self.w - 3
    local text = self.input_text
    if ulen(text) > room then text = usub(text, ulen(text) - room + 1) end
    local shown = ulen(text)

    if text ~= "" then self.s:set(3, y, text, COLOR_BAR_TEXT, COLOR_BG) end
    self.s:set(3 + shown, y, "_", COLOR_ACCENT, COLOR_BG)
    -- Clear only what the previous, longer line left behind. Typing one character used
    -- to cost a full-width fill plus three sets; now it costs one set, and only a
    -- backspace pays for anything extra.
    if self.input_drawn and self.input_drawn > shown then
        self.s:fill(4 + shown, y, self.input_drawn - shown, 1, " ", COLOR_ACCENT, COLOR_BG)
    end
    self.input_drawn = shown
    self.dirty = true
end

-- One row up, freeing the bottom row of the scrollback. A single `copy` for the whole
-- area beats redrawing every line by a wide margin -- it is one call either way on a
-- buffer, but on the direct-GPU fallback it is one call instead of hundreds.
function Ui:_scroll()
    if self.used < self.rows then
        self.used = self.used + 1
        return self.top + self.used - 1
    end
    self.s:copy(1, self.top + 1, self.w, self.rows - 1, 0, -1)
    self.s:fill(1, self.bottom, self.w, 1, " ", COLOR_TEXT, COLOR_BG)
    return self.bottom
end

-- Breaks one chat message into screen-width lines without splitting a colour run across
-- a wrap unless it has to. `segments` is what chat_format.render_chat_segments returns:
-- a list of { text = ..., color = 0xRRGGBB or nil }.
local function wrap(segments, width)
    local lines, line, used = {}, {}, 0
    for i = 1, #segments do
        local seg = segments[i]
        local text, color = seg.text, seg.color
        while text ~= "" do
            local room = width - used
            if room <= 0 then
                lines[#lines + 1] = line
                line, used = {}, 0
                room = width
            end
            local take = ulen(text)
            if take <= room then
                line[#line + 1] = { text = text, color = color }
                used = used + take
                text = ""
            else
                line[#line + 1] = { text = usub(text, 1, room), color = color }
                text = usub(text, room + 1)
                lines[#lines + 1] = line
                line, used = {}, 0
            end
        end
    end
    if #line > 0 then lines[#lines + 1] = line end
    if #lines == 0 then lines[1] = { { text = "", color = nil } } end
    return lines
end

function Ui:chat(segments)
    local lines = wrap(segments, self.w - 1)
    for i = 1, #lines do
        local y = self:_scroll()
        local x = 1
        local parts = lines[i]
        for j = 1, #parts do
            local part = parts[j]
            if part.text ~= "" then
                self.s:set(x, y, part.text, part.color or COLOR_TEXT, COLOR_BG)
                x = x + ulen(part.text)
            end
        end
    end
    self.dirty = true
end

-- A line of our own (a sent message, a note from the program itself).
function Ui:note(text, color)
    self:chat({ { text = text, color = color or COLOR_DIM } })
end

function Ui:status(text)
    if text == self.status_text then return end
    self.status_text = text
    self:_draw_status()
end

function Ui:input(text)
    if text == self.input_text then return end
    self.input_text = text
    self:_draw_input()
end

-- Push to the screen -- but at most once per game tick, and only if something changed.
--
-- This rate limit is what makes the buffer pay for itself, and leaving it out makes the
-- buffer actively worse than drawing straight to the card. The main loop calls flush()
-- after every packet, and during a burst (a chat flood, or the 45KB registry message
-- arriving in pieces) that is far more often than the screen can change anyway: a tick
-- is 0.05s, so anything more frequent is work nobody can see. Holding the writes lets
-- several chat lines collapse into one screen update, which is the whole point of
-- drawing into video memory first.
local PRESENT_INTERVAL = 0.05 -- one game tick

function Ui:flush(force)
    if not self.dirty then return end
    local now = self.clock()
    if not force and (now - self.last_present) < PRESENT_INTERVAL then return end
    self.last_present = now
    self.s:present()
    self.dirty = false
end

function Ui:close()
    self.s:fill(1, 1, self.w, self.h, " ", COLOR_TEXT, COLOR_BG)
    self.s:present()
    if self.s.close then self.s:close() end
    if self.gpu then
        self.gpu.setForeground(0xFFFFFF)
        self.gpu.setBackground(0x000000)
    end
end

M.COLOR_OK = COLOR_OK
M.COLOR_WARN = COLOR_WARN
M.COLOR_DIM = COLOR_DIM
M.COLOR_ACCENT = COLOR_ACCENT

return M
