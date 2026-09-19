local proto=require("mc_protocol")
local trace=require("trace")
local M={}
M.CHANNEL_REGISTER="REGISTER"
M.CHANNEL_HS="FML|HS"
M.CHANNEL_FML="FML"
local FML_PROTOCOL_VERSION=2
local DISC_SERVER_HELLO=0
local DISC_CLIENT_HELLO=1
local DISC_MOD_LIST=2
local DISC_MOD_ID_DATA=3
local DISC_HANDSHAKE_ACK=-1
local ORD_WAITINGSERVERDATA=2
local ORD_WAITINGSERVERCOMPLETE=3
local ORD_PENDINGCOMPLETE=4
local ORD_COMPLETE=5
local function write_i8(v)
if v<0 then v=v+256 end
return string.char(v%256)
end
local function encode_register(channels)
local out={M.CHANNEL_HS,M.CHANNEL_FML}
for i=1,#channels do
local name=channels[i]
if name~=M.CHANNEL_HS and name~=M.CHANNEL_FML then
out[#out+1]=name
end
end
return table.concat(out,"\0")
end
local function encode_client_hello()
return write_i8(DISC_CLIENT_HELLO)..write_i8(FML_PROTOCOL_VERSION)
end
local mod_count=0
local function encode_mod_list(mods)
local parts,n,count={},1,0
for modid,version in pairs(mods)do
count=count+1
parts[n]=proto.write_string(modid)
parts[n+1]=proto.write_string(version)
n=n+2
end
mod_count=count
return write_i8(DISC_MOD_LIST)..proto.write_varint(count)..table.concat(parts)
end
local function encode_handshake_ack(phase)
return write_i8(DISC_HANDSHAKE_ACK)..write_i8(phase)
end
local FmlHandshake={}
FmlHandshake.__index=FmlHandshake
function M.new(local_mod_list,send_payload_fn,channels)
return setmetatable({
register_payload=encode_register(channels or require("channels")),
mod_list_payload=encode_mod_list(local_mod_list),
mod_count=mod_count,
send_payload=send_payload_fn,
state="HELLO",
done=false,
restart_count=0,
},FmlHandshake)
end
function FmlHandshake:release()
self.register_payload=nil
self.mod_list_payload=nil
end
function FmlHandshake:handle_payload(channel,data)
if channel~=M.CHANNEL_HS then
return
end
if#data==0 then return end
local reader=proto.new_reader(data)
local discriminator=string.byte(reader:read(1))
if discriminator>=128 then discriminator=discriminator-256 end
self:_on_message(discriminator,reader)
end
function FmlHandshake:_on_message(discriminator,reader)
if discriminator==DISC_SERVER_HELLO then
if self.state~="HELLO"then
self.restart_count=self.restart_count+1
end
if not self.mod_list_payload then
error("FML handshake restarted after release(): the mod list is gone")
end
trace.step(self.state=="HELLO"and"FML: Server Hello"
or"FML: Server Hello заново (передача на другой сервер)")
if self.state=="HELLO"then
self.send_payload(M.CHANNEL_REGISTER,self.register_payload)
trace.step(string.format("FML: объявил каналы (%d Б) и %d модов (%d Б)",
#self.register_payload,self.mod_count,#self.mod_list_payload))
end
self.send_payload(M.CHANNEL_HS,encode_client_hello())
self.send_payload(M.CHANNEL_HS,self.mod_list_payload)
self.state="WAITINGSERVERDATA"
self.done=false
elseif self.state=="WAITINGSERVERDATA"then
if discriminator~=DISC_MOD_LIST then return end
trace.step("FML: получил список модов сервера")
self.send_payload(M.CHANNEL_HS,encode_handshake_ack(ORD_WAITINGSERVERDATA))
self.state="WAITINGSERVERCOMPLETE"
elseif self.state=="WAITINGSERVERCOMPLETE"then
if discriminator<DISC_MOD_ID_DATA then return end
trace.step("FML: получил реестр блоков и предметов")
self.send_payload(M.CHANNEL_HS,encode_handshake_ack(ORD_WAITINGSERVERCOMPLETE))
self.state="PENDINGCOMPLETE"
elseif self.state=="PENDINGCOMPLETE"then
self.send_payload(M.CHANNEL_HS,encode_handshake_ack(ORD_PENDINGCOMPLETE))
self.state="COMPLETE"
elseif self.state=="COMPLETE"then
self.send_payload(M.CHANNEL_HS,encode_handshake_ack(ORD_COMPLETE))
self.state="DONE"
self.done=true
trace.step("FML: рукопожатие завершено")
end
end
return M
