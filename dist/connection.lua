local internet=require("internet")
local proto=require("mc_protocol")
local fml=require("fml")
local rsa=require("rsa")
local sha1=require("sha1")
local rng=require("rng")
local PROTOCOL_VERSION=5
local HANDSHAKE_SET_PROTOCOL=0x00
local LOGIN_START=0x00
local ENCRYPTION_RESPONSE=0x01
local LOGIN_DISCONNECT=0x00
local ENCRYPTION_REQUEST=0x01
local LOGIN_SUCCESS=0x02
local KEEP_ALIVE=0x00
local CHAT_SERVERBOUND=0x01
local CLIENT_STATUS=0x16
local CLIENT_SETTINGS=0x15
local CUSTOM_PAYLOAD_SERVERBOUND=0x17
local KEEP_ALIVE_CLIENTBOUND=0x00
local JOIN_GAME_CLIENTBOUND=0x01
local CHAT_CLIENTBOUND=0x02
local CUSTOM_PAYLOAD_CLIENTBOUND=0x3F
local KICK_DISCONNECT_CLIENTBOUND=0x40
local M={}
local function server_hash_hex(server_id,shared_secret,public_key_der)
local digest=sha1.hash(server_id..shared_secret..public_key_der)
local is_negative=string.byte(digest,1)>=0x80
if not is_negative then
local hex=digest:gsub(".",function(c)return string.format("%02x",string.byte(c))end)
return(hex:gsub("^0+(.)","%1"))
end
local bytes={string.byte(digest,1,20)}
for i=1,20 do bytes[i]=255-bytes[i]end
local carry=1
for i=20,1,-1 do
bytes[i]=bytes[i]+carry
if bytes[i]>255 then
bytes[i]=bytes[i]-256
carry=1
else
carry=0
end
end
local hex={}
for i=1,20 do hex[i]=string.format("%02x",bytes[i])end
return"-"..(table.concat(hex):gsub("^0+(.)","%1"))
end
M.server_hash_hex=server_hash_hex
local function write_java_utf(s)
local n=#s
return string.char(math.floor(n/256),n%256)..s
end
local function build_login_extras()
local hwid=require("hwid")
local parts={}
for i=1,#hwid.fields do
parts[i]=write_java_utf("\1"..hwid.fields[i])
end
local locale=hwid.locale
package.loaded["hwid"]=nil
return locale,table.concat(parts)
end
local GhostConnection={}
GhostConnection.__index=GhostConnection
function M.new(host,port,session,local_mod_list,join_server_fn,yield_fn,cluster)
local locale,extras=build_login_extras()
return setmetatable({
host=host,
port=port,
session=session,
local_mod_list=local_mod_list,
join_server_fn=join_server_fn,
yield_fn=yield_fn or function()os.sleep(0)end,
cluster=cluster,
locale=locale,
login_extras=extras,
conn=nil,
fml_handshake=nil,
entity_id=nil,
},GhostConnection)
end
function GhostConnection:_send_custom_payload(channel,data)
self.conn:send_packet(CUSTOM_PAYLOAD_SERVERBOUND,
proto.write_string(channel)..proto.write_ushort(#data)..data)
end
function GhostConnection:connect()
local handle,err=internet.open(self.host,self.port)
if not handle then
error("failed to connect to "..self.host..":"..self.port..": "..tostring(err))
end
self.conn=proto.new_connection(handle,self.yield_fn,self.cluster)
self.conn:send_packet(HANDSHAKE_SET_PROTOCOL,
proto.write_varint(PROTOCOL_VERSION)
..proto.write_string(self.host)
..proto.write_ushort(self.port)
..proto.write_varint(2))
self.conn:send_packet(LOGIN_START,
proto.write_string(self.locale)
..proto.write_string(self.session.username)
..self.login_extras)
self.login_extras=nil
local packet_id,reader=self.conn:read_packet()
if packet_id==LOGIN_DISCONNECT then
error("disconnected during login: "..reader:read_string())
elseif packet_id==ENCRYPTION_REQUEST then
self:_do_encryption(reader)
elseif packet_id~=LOGIN_SUCCESS then
error(string.format("unexpected packet 0x%02x during login",packet_id))
end
self.fml_handshake=fml.new(self.local_mod_list,function(ch,data)
self:_send_custom_payload(ch,data)
end)
self.local_mod_list=nil
package.loaded["modlist"]=nil
package.loaded["channels"]=nil
require("computer").freeMemory()
end
function GhostConnection:_do_encryption(reader)
local server_id=reader:read_string()
local pubkey_len=reader:read_i16()
local public_key_der=reader:read(pubkey_len)
local verify_token_len=reader:read_i16()
local verify_token=reader:read(verify_token_len)
local n,e,mod_len=rsa.parse_public_key(public_key_der)
local shared_secret=rng.random_bytes(16)
local digest_hex=server_hash_hex(server_id,shared_secret,public_key_der)
self.join_server_fn(self.session.access_token,(self.session.uuid:gsub("-","")),digest_hex)
local enc_secret=rsa.encrypt(n,e,mod_len,shared_secret,rng.random_byte,self.yield_fn)
local enc_token=rsa.encrypt(n,e,mod_len,verify_token,rng.random_byte,self.yield_fn)
self.conn:send_packet(ENCRYPTION_RESPONSE,
proto.write_ushort(#enc_secret)..enc_secret
..proto.write_ushort(#enc_token)..enc_token)
self.conn:enable_encryption(shared_secret)
local packet_id,reader2=self.conn:read_packet()
if packet_id==LOGIN_DISCONNECT then
error("disconnected after encryption: "..reader2:read_string())
elseif packet_id~=LOGIN_SUCCESS then
error(string.format("expected Login Success, got 0x%02x",packet_id))
end
end
function GhostConnection:send_chat(message)
self.conn:send_packet(CHAT_SERVERBOUND,proto.write_string(message))
end
function GhostConnection:_send_initial_packets()
self.conn:send_packet(CLIENT_STATUS,"\0")
self.conn:send_packet(CLIENT_SETTINGS,
proto.write_string(self.locale)
..string.char(8)
..string.char(0)
.."\1"
..string.char(2)
.."\1")
end
function GhostConnection:run(on_chat,on_join)
local conn,handshake=self.conn,self.fml_handshake
while true do
local ok,packet_id,reader=pcall(conn.read_packet,conn)
if not ok then
return"connection closed unexpectedly: "..tostring(packet_id)
end
if packet_id==KEEP_ALIVE_CLIENTBOUND then
conn:send_packet(KEEP_ALIVE,reader:read(4))
elseif packet_id==CHAT_CLIENTBOUND then
if on_chat then on_chat(reader:read_string())end
elseif packet_id==CUSTOM_PAYLOAD_CLIENTBOUND then
local channel=reader:read_string()
local data_len=reader:read_i16()
handshake:handle_payload(channel,reader:read(data_len))
elseif packet_id==JOIN_GAME_CLIENTBOUND then
self.entity_id=reader:read(4)
self:_send_initial_packets()
if on_join then on_join(self.entity_id)end
elseif packet_id==KICK_DISCONNECT_CLIENTBOUND then
return reader:read_string()
end
self.yield_fn()
end
end
function GhostConnection:close()
if self.conn then self.conn:close()end
end
return M
