--[[
Flattens 1.7.10-era Minecraft chat component JSON (nested {"text","extra","color",...}
objects) into a readable, ANSI-colored string. Straight port of ghost_client's Python
chat_format.py -- see that file for the reference behavior this mirrors.

Ships its own minimal JSON decoder (object/array/string/number/true/false/null, enough
for chat component payloads) so this module stays dependency-free like the rest of
ghost_client_lua.
]]
local M = {}

local RESET = "\27[0m"

local COLOR_CODES = {
    black = "\27[30m",
    dark_blue = "\27[34m",
    dark_green = "\27[32m",
    dark_aqua = "\27[36m",
    dark_red = "\27[31m",
    dark_purple = "\27[35m",
    gold = "\27[33m",
    gray = "\27[37m",
    dark_gray = "\27[90m",
    blue = "\27[94m",
    green = "\27[92m",
    aqua = "\27[96m",
    red = "\27[91m",
    light_purple = "\27[95m",
    yellow = "\27[93m",
    white = "\27[97m",
}

-- Same 16 colors as vanilla Minecraft chat, as 0xRRGGBB -- used by render_chat_segments
-- below for real GPU-rendered color (an OpenComputers terminal doesn't interpret ANSI
-- escape codes at all, unlike a real terminal, so the ANSI-string path above is no use
-- there; see main.lua's print_colored for how these get turned into actual color).
local COLOR_HEX = {
    black = 0x000000,
    dark_blue = 0x0000AA,
    dark_green = 0x00AA00,
    dark_aqua = 0x00AAAA,
    dark_red = 0xAA0000,
    dark_purple = 0xAA00AA,
    gold = 0xFFAA00,
    gray = 0xAAAAAA,
    dark_gray = 0x555555,
    blue = 0x5555FF,
    green = 0x55FF55,
    aqua = 0x55FFFF,
    red = 0xFF5555,
    light_purple = 0xFF55FF,
    yellow = 0xFFFF55,
    white = 0xFFFFFF,
}

-- Minecraft's own legacy "\xc2\xa7"(UTF-8 for U+00A7)+code formatting -- as opposed to
-- the JSON chat component "color" attribute render_node otherwise handles. Some
-- servers/plugins (seen in the wild on this one) embed these directly inside a
-- message's plain text instead of (or on top of) proper component colors.
local SECTION_SIGN = "\194\167"
local LEGACY_COLOR_ANSI = {
    ["0"] = "\27[30m", ["1"] = "\27[34m", ["2"] = "\27[32m", ["3"] = "\27[36m",
    ["4"] = "\27[31m", ["5"] = "\27[35m", ["6"] = "\27[33m", ["7"] = "\27[37m",
    ["8"] = "\27[90m", ["9"] = "\27[94m", a = "\27[92m", b = "\27[96m",
    c = "\27[91m", d = "\27[95m", e = "\27[93m", f = "\27[97m",
}
local LEGACY_FORMAT_ANSI = { l = "\27[1m", o = "\27[3m", n = "\27[4m", m = "\27[9m", k = "" }
local LEGACY_COLOR_HEX = {
    ["0"] = 0x000000, ["1"] = 0x0000AA, ["2"] = 0x00AA00, ["3"] = 0x00AAAA,
    ["4"] = 0xAA0000, ["5"] = 0xAA00AA, ["6"] = 0xFFAA00, ["7"] = 0xAAAAAA,
    ["8"] = 0x555555, ["9"] = 0x5555FF, a = 0x55FF55, b = 0x55FFFF,
    c = 0xFF5555, d = 0xFF55FF, e = 0xFFFF55, f = 0xFFFFFF,
}

-- ---------------------------------------------------------------------------
-- Minimal JSON decoder. Unique table (not a string) used to mark JSON-array tables
-- so render_node below can tell an array apart from an object -- both decode to plain
-- Lua tables, and a table key can never collide with a JSON string key.
local ARRAY_MARKER = {}

local function skip_ws(s, i)
    local _, j = s:find("^[ \t\r\n]*", i)
    return j + 1
end

local decode_value -- forward decl, mutually recursive with the three below

local function decode_string(s, i)
    local j = i + 1 -- skip opening quote
    local out = {}
    while true do
        local c = s:sub(j, j)
        if c == "" then
            error("unterminated JSON string")
        elseif c == '"' then
            return table.concat(out), j + 1
        elseif c == "\\" then
            local esc = s:sub(j + 1, j + 1)
            if esc == "u" then
                local hex = s:sub(j + 2, j + 5)
                local code = tonumber(hex, 16)
                if not code then error("bad \\u escape in JSON string") end
                -- Chat components in this era stick to BMP text in practice; encode as
                -- UTF-8 (no surrogate-pair handling needed for that range).
                if code < 0x80 then
                    out[#out + 1] = string.char(code)
                elseif code < 0x800 then
                    out[#out + 1] = string.char(0xC0 + math.floor(code / 0x40), 0x80 + (code % 0x40))
                else
                    out[#out + 1] = string.char(
                        0xE0 + math.floor(code / 0x1000),
                        0x80 + (math.floor(code / 0x40) % 0x40),
                        0x80 + (code % 0x40)
                    )
                end
                j = j + 6
            else
                local map = { ['"'] = '"', ["\\"] = "\\", ["/"] = "/", b = "\b", f = "\f", n = "\n", r = "\r", t = "\t" }
                local rep = map[esc]
                if not rep then error("bad escape \\" .. esc .. " in JSON string") end
                out[#out + 1] = rep
                j = j + 2
            end
        else
            out[#out + 1] = c
            j = j + 1
        end
    end
end

local function decode_array(s, i)
    local arr = { [ARRAY_MARKER] = true }
    local j = skip_ws(s, i + 1)
    if s:sub(j, j) == "]" then
        return arr, j + 1
    end
    while true do
        local val
        val, j = decode_value(s, j)
        arr[#arr + 1] = val
        j = skip_ws(s, j)
        local c = s:sub(j, j)
        if c == "]" then
            return arr, j + 1
        elseif c ~= "," then
            error("expected ',' or ']' in JSON array")
        end
        j = skip_ws(s, j + 1)
    end
end

local function decode_object(s, i)
    local obj = {}
    local j = skip_ws(s, i + 1)
    if s:sub(j, j) == "}" then
        return obj, j + 1
    end
    while true do
        if s:sub(j, j) ~= '"' then error("expected string key in JSON object") end
        local key
        key, j = decode_string(s, j)
        j = skip_ws(s, j)
        if s:sub(j, j) ~= ":" then error("expected ':' in JSON object") end
        j = skip_ws(s, j + 1)
        local val
        val, j = decode_value(s, j)
        obj[key] = val
        j = skip_ws(s, j)
        local c = s:sub(j, j)
        if c == "}" then
            return obj, j + 1
        elseif c ~= "," then
            error("expected ',' or '}' in JSON object")
        end
        j = skip_ws(s, j + 1)
    end
end

decode_value = function(s, i)
    i = skip_ws(s, i)
    local c = s:sub(i, i)
    if c == '"' then
        return decode_string(s, i)
    elseif c == "{" then
        return decode_object(s, i)
    elseif c == "[" then
        return decode_array(s, i)
    elseif s:sub(i, i + 3) == "true" then
        return true, i + 4
    elseif s:sub(i, i + 4) == "false" then
        return false, i + 5
    elseif s:sub(i, i + 3) == "null" then
        return nil, i + 4
    else
        local numstr = s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*", i)
        if not numstr or numstr == "" then
            error("unexpected character in JSON at position " .. i)
        end
        local n = tonumber(numstr)
        if not n then error("bad JSON number") end
        return n, i + #numstr
    end
end

local function decode(s)
    local val, j = decode_value(s, 1)
    j = skip_ws(s, j)
    if j <= #s then
        error("trailing data after JSON value")
    end
    return val
end
M.decode = decode

-- ---------------------------------------------------------------------------

-- Scans `text` for section-sign codes, converting each to the matching ANSI escape
-- (dropping formatting codes with no sane ANSI equivalent, e.g. obfuscated). Used by
-- the plain ANSI-string render path (render_chat_json) -- render_chat_segments below
-- has its own equivalent that tracks 0xRRGGBB instead, since that's what actually
-- renders as color on an OpenComputers terminal.
local function render_legacy_ansi(text)
    if not text:find(SECTION_SIGN, 1, true) then
        return text
    end
    local pieces = {}
    local i = 1
    local n = #text
    while i <= n do
        if text:sub(i, i + 1) == SECTION_SIGN and i + 2 <= n then
            local code = text:sub(i + 2, i + 2):lower()
            pieces[#pieces + 1] = LEGACY_COLOR_ANSI[code] or LEGACY_FORMAT_ANSI[code] or (code == "r" and RESET) or ""
            i = i + 3
        else
            pieces[#pieces + 1] = text:sub(i, i)
            i = i + 1
        end
    end
    pieces[#pieces + 1] = RESET
    return table.concat(pieces)
end

local function render_node(node, inherited_color)
    local t = type(node)
    if t == "string" then
        return node
    end

    if t == "table" then
        if node[ARRAY_MARKER] then
            local pieces = {}
            for _, child in ipairs(node) do
                pieces[#pieces + 1] = render_node(child, inherited_color)
            end
            return table.concat(pieces)
        end

        local color = node.color or inherited_color
        local code = (color and COLOR_CODES[color]) or ""

        local pieces = {}
        local text = node.text
        if text and text ~= "" then
            text = render_legacy_ansi(text)
            pieces[#pieces + 1] = (code ~= "" and (code .. text .. RESET)) or text
        end

        if node.extra then
            for _, extra in ipairs(node.extra) do
                pieces[#pieces + 1] = render_node(extra, color)
            end
        end

        return table.concat(pieces)
    end

    return ""
end

-- Best-effort: falls back to the raw string (with any legacy section-sign codes it
-- contains still converted) if it isn't valid/expected JSON, so a malformed or
-- unexpected payload never crashes the caller. Not every server sends proper JSON
-- chat components -- some chat messages (seen in the wild on this one) arrive as a
-- bare legacy-formatted string instead of a {text=...} object, which previously meant
-- their section-sign codes were never touched at all (that conversion only ran inside
-- the JSON-tree walk below).
function M.render_chat_json(raw)
    local ok, data = pcall(decode, raw)
    if not ok then
        return render_legacy_ansi(raw)
    end
    local ok2, result = pcall(render_node, data, nil)
    if not ok2 then
        return render_legacy_ansi(raw)
    end
    return result
end

-- ---------------------------------------------------------------------------
-- Structured rendering: a flat list of {text=, color=<0xRRGGBB or nil>} runs, for
-- callers (main.lua) that can actually set a real terminal color per run (via
-- gpu.setForeground) rather than embedding an ANSI escape OpenComputers won't
-- interpret. `color=nil` means "whatever the terminal's default is".

-- Splits `text` on embedded section-sign codes, appending {text=,color=} runs to
-- `out`. `color` is the run color in effect going in (from the enclosing JSON node);
-- a legacy color code switches it for the rest of *this* text, a legacy "r" resets to
-- no color -- matching vanilla behavior, where these codes don't reach outside the
-- text run they appear in.
local function split_legacy(text, color, out)
    if not text:find(SECTION_SIGN, 1, true) then
        if text ~= "" then out[#out + 1] = { text = text, color = color } end
        return
    end
    local buf = {}
    local function flush()
        if #buf > 0 then
            out[#out + 1] = { text = table.concat(buf), color = color }
            buf = {}
        end
    end
    local i = 1
    local n = #text
    while i <= n do
        if text:sub(i, i + 1) == SECTION_SIGN and i + 2 <= n then
            flush()
            local code = text:sub(i + 2, i + 2):lower()
            if LEGACY_COLOR_HEX[code] then
                color = LEGACY_COLOR_HEX[code]
            elseif code == "r" then
                color = nil
            end
            -- formatting-only codes (l/o/n/m/k) have no terminal-color equivalent; skip
            i = i + 3
        else
            buf[#buf + 1] = text:sub(i, i)
            i = i + 1
        end
    end
    flush()
end

local function render_node_segments(node, inherited_color, out)
    local t = type(node)
    if t == "string" then
        split_legacy(node, inherited_color, out)
        return
    end

    if t == "table" then
        if node[ARRAY_MARKER] then
            for _, child in ipairs(node) do
                render_node_segments(child, inherited_color, out)
            end
            return
        end

        local color = inherited_color
        if node.color and COLOR_HEX[node.color] then
            color = COLOR_HEX[node.color]
        end

        local text = node.text
        if text and text ~= "" then
            split_legacy(text, color, out)
        end

        if node.extra then
            for _, extra in ipairs(node.extra) do
                render_node_segments(extra, color, out)
            end
        end
    end
end

-- Best-effort, same fallback behavior as render_chat_json: an unparseable payload
-- still gets its legacy section-sign codes split into colored segments (see that
-- function's comment -- not every message is proper JSON), falling back further to a
-- single plain (uncolored) segment only if even that fails.
function M.render_chat_segments(raw)
    local ok, data = pcall(decode, raw)
    if not ok then
        local out = {}
        local split_ok = pcall(split_legacy, raw, nil, out)
        if split_ok and #out > 0 then
            return out
        end
        return { { text = raw, color = nil } }
    end
    local out = {}
    local ok2 = pcall(render_node_segments, data, nil, out)
    if not ok2 or #out == 0 then
        return { { text = raw, color = nil } }
    end
    return out
end

return M
