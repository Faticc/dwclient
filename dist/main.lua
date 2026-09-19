local computer=require("computer")
local connection=require("connection")
local session_mod=require("session")
local chat_format=require("chat_format")
local cluster_client=require("cluster_client")
local ui_lib=require("ui")
local SESSION={
username="YourNick",
uuid="00000000-0000-0000-0000-000000000000",
access_token="PUT-A-FRESH-SESSION-ID-HERE",
}
local HOST="proxy-1.metalabsmc.net"
local PORT=25606
local keyboard_ok,keyboard=pcall(require,"keyboard")
local event_ok,event=pcall(require,"event")
local unicode_ok,unicode=pcall(require,"unicode")
local input_enabled=keyboard_ok and event_ok
local process_ok,process=pcall(require,"process")
if process_ok and process.killable then pcall(process.killable,false)end
local ui=ui_lib.new({title="ghost . "..SESSION.username.."@"..HOST..":"..PORT})
local function say(text,color)
if ui then ui:note(text,color)else print(text)end
end
local cluster=cluster_client.new()
local conn
local connected=false
local input_buf={}
local last_status=0
local function status_line()
local total,free=computer.totalMemory(),computer.freeMemory()
return string.format("mem %dK/%dK  %s",(total-free)/1024,total/1024,
connected and"connected"or"connecting")
end
local function handle_key_down(char,code)
if code==keyboard.keys.enter or code==keyboard.keys.numpadenter then
local line=table.concat(input_buf)
input_buf={}
if ui then ui:input("")end
if line~=""and connected then
local ok,err=pcall(conn.send_chat,conn,line)
if ok then
say("> "..line,ui_lib.COLOR_ACCENT)
else
say("!! failed to send: "..tostring(err),ui_lib.COLOR_WARN)
end
end
elseif code==keyboard.keys.back then
if#input_buf>0 then
table.remove(input_buf)
if ui then ui:input(table.concat(input_buf))end
end
elseif char and char>=32 then
local ch
if unicode_ok then
local ok,u=pcall(unicode.char,char)
ch=ok and u or nil
elseif char<256 then
ch=string.char(char)
end
if ch then
input_buf[#input_buf+1]=ch
if ui then ui:input(table.concat(input_buf))end
end
end
end
local stop_requested=false
local function yield()
if input_enabled then
local ev,_,char,code=event.pull(0,"key_down")
if ev=="key_down"then
pcall(handle_key_down,char,code)
elseif ev=="interrupted"then
stop_requested=true
end
else
os.sleep(0)
end
if ui then
local now=computer.uptime()
if now-last_status>=1 then
last_status=now
ui:status(status_line())
end
ui:flush()
end
end
local function join_server_fn(access_token,uuid_no_dashes,server_hash)
session_mod.join_server(access_token,uuid_no_dashes,server_hash)
end
conn=connection.new(HOST,PORT,SESSION,require("modlist"),join_server_fn,yield,cluster)
say(cluster:available()
and("cluster decrypt: "..#cluster.tunnels.." Linked Card worker(s)")
or"cluster decrypt: off (no Linked Cards, decrypting locally)")
say("connecting to "..HOST..":"..PORT.." as "..SESSION.username.." ...")
if ui then ui:flush(true)end
local ok,err=pcall(conn.connect,conn)
if not ok then
say("connect failed: "..tostring(err),ui_lib.COLOR_WARN)
if ui then ui:flush(true)end
return
end
connected=true
say("logged in, waiting for the world",ui_lib.COLOR_OK)
_G.ghost_send_chat=function(message)
conn:send_chat(message)
say("> "..message,ui_lib.COLOR_ACCENT)
end
local function on_chat(raw_json)
if ui then
ui:chat(chat_format.render_chat_segments(raw_json))
else
print(chat_format.render_chat_json(raw_json))
end
end
local function on_join()
say("joined the world",ui_lib.COLOR_OK)
end
local reason=conn:run(on_chat,on_join)
connected=false
conn:close()
if ui then
ui:note("disconnected: "..tostring(reason),ui_lib.COLOR_WARN)
ui:status("disconnected -- press any key to exit")
ui:flush(true)
if input_enabled and not stop_requested then event.pull(30,"key_down")end
ui:close()
end
print("disconnected: "..tostring(reason))
