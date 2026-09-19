local component=require("component")
local event=require("event")
local M={}
local Cluster={}
Cluster.__index=Cluster
function M.new(opts)
opts=opts or{}
local tunnels={}
local ok,addresses=pcall(component.list,"tunnel")
if ok and addresses then
for address in pairs(addresses)do
local proxy_ok,proxy=pcall(component.proxy,address)
if proxy_ok and proxy then
tunnels[#tunnels+1]=proxy
end
end
end
return setmetatable({
tunnels=tunnels,
chunk_size=opts.chunk_size or 1024,
min_size=opts.min_size or 2048,
timeout=opts.timeout or 5,
command=opts.command or"ghost-cfb8-decrypt",
request_seq=0,
},Cluster)
end
function Cluster:available()
return#self.tunnels>0
end
function Cluster:_next_request_id()
self.request_seq=self.request_seq+1
return tostring(os.time()).."-"..tostring(self.request_seq)
end
function Cluster:_send_chunks(ciphertext,key,iv0,request_id)
local chunk_count=math.ceil(#ciphertext/self.chunk_size)
for chunk_id=1,chunk_count do
local start_index=(chunk_id-1)*self.chunk_size+1
local end_index=math.min(chunk_id*self.chunk_size,#ciphertext)
local tunnel=self.tunnels[((chunk_id-1)%#self.tunnels)+1]
local iv=start_index==1 and iv0 or ciphertext:sub(start_index-16,start_index-1)
local chunk=ciphertext:sub(start_index,end_index)
tunnel.send(self.command,request_id,chunk_id,key,iv,chunk)
end
return chunk_count
end
function Cluster:_receive_chunks(chunk_count,request_id,yield_fn)
local results={}
local received=0
local deadline=os.clock()+self.timeout
while received<chunk_count do
if os.clock()>=deadline then
error("cluster decrypt timed out: "..received.."/"..chunk_count.." chunks")
end
local _,_,_,_,_,message_type,req_id,chunk_id,payload=event.pull(1,"modem_message")
if message_type==self.command.."-error"and req_id==request_id then
error("cluster worker reported error on chunk "..tostring(chunk_id)..": "..tostring(payload))
elseif message_type==self.command.."-result"and req_id==request_id and results[chunk_id]==nil then
results[chunk_id]=payload
received=received+1
end
if yield_fn then yield_fn()end
end
return table.concat(results)
end
function Cluster:decrypt(ciphertext,key,iv0,yield_fn)
if not self:available()then
error("cluster decrypt requested but no Linked Cards (tunnel components) found")
end
local request_id=self:_next_request_id()
local chunk_count=self:_send_chunks(ciphertext,key,iv0,request_id)
return self:_receive_chunks(chunk_count,request_id,yield_fn)
end
return M
