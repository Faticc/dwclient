package.path = package.path .. ";./?.lua"
local chat_format = require("chat_format")

local all_ok = true

local function check(name, got, expected)
    local ok = got == expected
    all_ok = all_ok and ok
    print(string.format("%-28s got=%-40s expected=%-40s %s", name, got, expected, ok and "OK" or "FAIL"))
end

check("flat_text", chat_format.render_chat_json('{"text":"hello"}'), "hello")

check(
    "colored_text",
    chat_format.render_chat_json('{"text":"hi","color":"gold"}'),
    "\27[33mhi\27[0m"
)

check(
    "invalid_json_falls_back",
    chat_format.render_chat_json("not json"),
    "not json"
)

do
    local raw = '{"color":"dark_gray","text":"[","extra":['
        .. '{"color":"gold","text":"G"},'
        .. '{"color":"dark_gray","text":"] "},'
        .. '{"color":"white","text":"hi there"}'
        .. "]}"
    local rendered = chat_format.render_chat_json(raw)
    local has_g = rendered:find("G", 1, true) ~= nil
    local has_hi = rendered:find("hi there", 1, true) ~= nil
    local order_ok = has_g and has_hi and (rendered:find("G", 1, true) < rendered:find("hi there", 1, true))
    local ok = has_g and has_hi and order_ok
    all_ok = all_ok and ok
    print(string.format("%-28s %s", "nested_extra_and_color", ok and "OK" or "FAIL"))
end

do
    -- color inherited from the parent node down into "extra" children that don't
    -- specify their own.
    local rendered = chat_format.render_chat_json('{"color":"red","text":"a","extra":[{"text":"b"}]}')
    local expected = "\27[31ma\27[0m\27[31mb\27[0m"
    check("inherited_color", rendered, expected)
end

os.exit(all_ok and 0 or 1)
