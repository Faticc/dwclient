local component=require("component")
local computer=require("computer")
local M={}
M.JOIN_URL="https://auth.mcskill.ru/join1710"
local function json_escape(s)
return(s:gsub('[\\"]',"\\%0"))
end
function M.join_server(access_token,uuid_no_dashes,server_hash)
if not component.isAvailable("internet")then
error("no Internet Card found -- join_server needs one to reach auth.mcskill.ru")
end
local inet=component.internet
local body=string.format(
'{"accessToken":"%s","selectedProfile":"%s","serverId":"%s"}',
json_escape(access_token),json_escape(uuid_no_dashes),json_escape(server_hash)
)
local request,err=inet.request(M.JOIN_URL,body,{["Content-Type"]="application/json"},"POST")
if not request then
error("join_server request failed to start: "..tostring(err))
end
while true do
local chunk,reason=request.read()
if chunk==nil then
if reason then
request.close()
error("join_server request failed: "..tostring(reason))
end
break
elseif#chunk==0 then
computer.pullSignal(0)
end
end
local ok,code,message=pcall(function()
if type(request.response)=="function"then
return request.response()
end
local mt=getmetatable(request)
if mt and mt.__index and type(mt.__index.response)=="function"then
return mt.__index.response()
end
return nil
end)
request.close()
if ok and code and code>=300 then
error(string.format("join_server failed (%d): %s",code,tostring(message)))
end
end
return M
