local cfb8=require("cfb8")
local trace=require("trace")
local M={}
local function default_yield()require("computer").pullSignal(0)end
local WATCHDOG_MARGIN=2.0
function M.throttled(yield_fn,interval)
local uptime=require("computer").uptime
local last=uptime()
interval=interval or WATCHDOG_MARGIN
return function(done,total)
local now=uptime()
if now-last>=interval then
last=now
yield_fn(done,total)
end
end
end
function M.read_exact(handle,n,yield_fn)
yield_fn=yield_fn or default_yield
local chunks={}
local remaining=n
while remaining>0 do
local chunk,err=handle:read(remaining)
if chunk==nil then
error("connection closed while reading "..n.." bytes ("..remaining.." left): "..tostring(err))
end
if#chunk>0 then
chunks[#chunks+1]=chunk
remaining=remaining-#chunk
end
yield_fn()
end
return table.concat(chunks)
end
function M.write_varint(value)
value=value%4294967296
local out={}
repeat
local byte=value%128
value=(value-byte)/128
if value~=0 then
out[#out+1]=string.char(byte+128)
else
out[#out+1]=string.char(byte)
end
until value==0
return table.concat(out)
end
function M.read_varint(handle)
local value=0
local shift=0
while true do
local byte=string.byte(M.read_exact(handle,1))
value=value+(byte%128)*(2^shift)
if byte<128 then break end
shift=shift+7
if shift>35 then error("VarInt too big")end
end
if value>=2147483648 then value=value-4294967296 end
return value
end
function M.write_string(s)
return M.write_varint(#s)..s
end
function M.write_ushort(n)
return string.char(math.floor(n/256)%256,n%256)
end
function M.write_int(value)
value=value%4294967296
local b3=value%256;value=(value-b3)/256
local b2=value%256;value=(value-b2)/256
local b1=value%256;value=(value-b1)/256
local b0=value%256
return string.char(b0,b1,b2,b3)
end
local ByteReader={}
ByteReader.__index=ByteReader
function M.new_reader(data)
return setmetatable({data=data,pos=1},ByteReader)
end
function ByteReader:read(n)
local chunk=self.data:sub(self.pos,self.pos+n-1)
self.pos=self.pos+n
return chunk
end
function ByteReader:read_i16()
local hi,lo=string.byte(self:read(2),1,2)
local v=hi*256+lo
if v>=32768 then v=v-65536 end
return v
end
function ByteReader:read_varint()
local value=0
local shift=0
while true do
local byte=string.byte(self:read(1))
value=value+(byte%128)*(2^shift)
if byte<128 then break end
shift=shift+7
end
if value>=2147483648 then value=value-4294967296 end
return value
end
function ByteReader:read_string()
local len=self:read_varint()
return self:read(len)
end
function ByteReader:remaining()
return self.data:sub(self.pos)
end
local Connection={}
Connection.__index=Connection
function M.new_connection(handle,yield_fn,cpu_yield)
yield_fn=yield_fn or default_yield
return setmetatable({
handle=handle,
enc_in=nil,
enc_out=nil,
yield_fn=yield_fn,
cpu_yield=cpu_yield or M.throttled(yield_fn),
},Connection)
end
function Connection:enable_encryption(shared_secret16)
self.enc_in=cfb8.Stream.new(shared_secret16)
self.enc_out=cfb8.Stream.new(shared_secret16)
end
local TRACE_DECRYPT_OVER=4096
function Connection:_raw_read(n)
local data=M.read_exact(self.handle,n,self.yield_fn)
if self.enc_in then
data=self.enc_in:decrypt(data,self.cpu_yield)
end
return data
end
function Connection:_read_varint_raw()
local value=0
local shift=0
while true do
local byte=string.byte(self:_raw_read(1))
value=value+(byte%128)*(2^shift)
if byte<128 then break end
shift=shift+7
end
if value>=2147483648 then value=value-4294967296 end
return value
end
local HEAD_BYTES=96
function Connection:read_packet(wants)
local length=self:_read_varint_raw()
if not self.enc_in then
self.last_length=length
local reader=M.new_reader(M.read_exact(self.handle,length,self.yield_fn))
return reader:read_varint(),reader
end
self.last_length=length
local raw=M.read_exact(self.handle,length,self.yield_fn)
local head_n=length<HEAD_BYTES and length or HEAD_BYTES
local head=self.enc_in:decrypt(raw:sub(1,head_n),self.cpu_yield)
local probe=M.new_reader(head)
local packet_id=probe:read_varint()
if wants and not wants(packet_id,probe)then
if length>head_n then self.enc_in:skip(raw:sub(head_n+1))end
local reader=M.new_reader(head)
reader:read_varint()
return packet_id,reader,true
end
local body=head
if length>head_n then
local loud=trace.enabled()and length>=TRACE_DECRYPT_OVER
if loud then trace.busy(string.format("расшифровка %d Б",length))end
body=head..self.enc_in:decrypt(raw:sub(head_n+1),self.cpu_yield)
if loud then trace.done(string.format("расшифровано %d Б",length))end
end
local reader=M.new_reader(body)
reader:read_varint()
return packet_id,reader
end
function Connection:send_packet(packet_id,payload)
payload=payload or""
local body=M.write_varint(packet_id)..payload
local framed=M.write_varint(#body)..body
if self.enc_out then
framed=self.enc_out:encrypt(framed,self.cpu_yield)
end
local ok,err=self.handle:write(framed)
if not ok then
error("failed to send packet: "..tostring(err))
end
end
function Connection:close()
self.handle:close()
end
return M
