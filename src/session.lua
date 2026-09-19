--[[
The join-server HTTP call only -- login itself is skipped entirely per this version's
whole point: the session (accessToken/uuid/username) is supplied by hand in main.lua
instead of calling McSkill's auth service from here.

Same endpoint ghost_client's Python session.py uses, confirmed by reading the real
client's own log line (see that file's header comment): McSkill's authlib runs in
"MODERN" mode, i.e. a plain Yggdrasil-shaped JSON POST, just against a custom,
per-Minecraft-version URL instead of the generic /sessionserver/... path.
]]
local component = require("component")

local M = {}

M.JOIN_URL = "https://auth.mcskill.ru/join1710"

local function json_escape(s)
    return (s:gsub('[\\"]', "\\%0"))
end

-- Performs the HTTP POST and drains the response. Raises an error (via Lua's error())
-- if the server responds with a non-2xx status, same as ghost_client's
-- JoinServerError.
function M.join_server(access_token, uuid_no_dashes, server_hash)
    if not component.isAvailable("internet") then
        error("no Internet Card found -- join_server needs one to reach auth.mcskill.ru")
    end
    local inet = component.internet

    local body = string.format(
        '{"accessToken":"%s","selectedProfile":"%s","serverId":"%s"}',
        json_escape(access_token), json_escape(uuid_no_dashes), json_escape(server_hash)
    )

    local request, err = inet.request(M.JOIN_URL, body, { ["Content-Type"] = "application/json" }, "POST")
    if not request then
        error("join_server request failed to start: " .. tostring(err))
    end

    -- Drain the response body (we don't need it, just need the request to finish so
    -- we can read the status code), yielding between polls the same way OpenOS's own
    -- internet.request iterator does.
    while true do
        local chunk, reason = request.read()
        if chunk == nil then
            if reason then
                request.close()
                error("join_server request failed: " .. tostring(reason))
            end
            break -- normal EOF
        elseif #chunk == 0 then
            os.sleep(0)
        end
    end

    -- Getting the HTTP status code back out is unfortunately not consistent across
    -- OpenComputers builds/versions -- some expose it as request.response(), others
    -- only through getmetatable(request).__index.response(). Try both, and if neither
    -- is there, just skip the status check: a real transport-level failure already
    -- raised above via `reason`, so this is only extra robustness against the server
    -- answering with a non-2xx status while still supplying a normal-looking body.
    local ok, code, message = pcall(function()
        if type(request.response) == "function" then
            return request.response()
        end
        local mt = getmetatable(request)
        if mt and mt.__index and type(mt.__index.response) == "function" then
            return mt.__index.response()
        end
        return nil
    end)
    request.close()

    if ok and code and code >= 300 then
        error(string.format("join_server failed (%d): %s", code, tostring(message)))
    end
end

return M
