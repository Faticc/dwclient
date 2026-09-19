local component=require("component")
local event=require("event")
local cfb8=require("cfb8")
local modem=component.modem
local PORT=1234
local COMMAND="ghost-cfb8-decrypt"
local REQUEST_ID=tostring(math.floor(os.time())).."-"..tostring(math.random(100000,999999))
local TEST_SIZE=14*1024
local CHUNK_SIZE=1024
local WORKERS={
"b088268f-d14b-4b30-907c-668499cbaa08",
"d7e55430-b0c8-41e3-9dc6-e9bfcbe5f6d8",
"fd113646-d0ef-4fc5-87e5-cb0d0a56ee02",
}
local key=string.char(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
local function make_payload(size)
local out={}
for i=1,size do
out[i]=string.char((i*37+math.floor(i/251))%256)
end
return table.concat(out)
end
local function encrypt_test_payload(plaintext)
return cfb8.Stream.new(key):encrypt(plaintext)
end
local function send_chunks(ciphertext)
local chunk_count=math.ceil(#ciphertext/CHUNK_SIZE)
for chunk_id=1,chunk_count do
local start_index=(chunk_id-1)*CHUNK_SIZE+1
local end_index=math.min(chunk_id*CHUNK_SIZE,#ciphertext)
local worker=WORKERS[((chunk_id-1)%#WORKERS)+1]
local iv=start_index==1 and key or ciphertext:sub(start_index-16,start_index-1)
local chunk=ciphertext:sub(start_index,end_index)
modem.send(worker,PORT,COMMAND,REQUEST_ID,chunk_id,key,iv,chunk)
end
return chunk_count
end
local function receive_chunks(chunk_count)
local results={}
local received=0
local deadline=os.clock()+30
while received<chunk_count do
if os.clock()>=deadline then
error("timeout waiting for modem workers: "..received.."/"..chunk_count)
end
local _,_,sender,port,_,message_type,request_id,chunk_id,payload=event.pull(1,"modem_message")
if port==PORT and request_id==REQUEST_ID then
if message_type==COMMAND.."-error"then
error("worker "..tostring(sender).." failed on chunk "..tostring(chunk_id)..": "..tostring(payload))
elseif message_type==COMMAND.."-result"and results[chunk_id]==nil then
results[chunk_id]=payload
received=received+1
end
end
end
return table.concat(results)
end
math.randomseed(os.time())
modem.open(PORT)
print("Master modem test: "..TEST_SIZE.." bytes, "..#WORKERS.." workers")
local plaintext=make_payload(TEST_SIZE)
local ciphertext=encrypt_test_payload(plaintext)
local start=os.clock()
local chunk_count=send_chunks(ciphertext)
local decrypted=receive_chunks(chunk_count)
local elapsed=os.clock()-start
print("chunks sent: "..chunk_count)
print(string.format("modem cluster time: %.3f sec",elapsed))
print("ciphertext size: "..#ciphertext.." bytes")
print("result: "..(decrypted==plaintext and"OK"or"FAIL"))
local cfb8=require("cfb8")
local TEST_SIZE=14*1024
local CHUNK_SIZE=1024
local key=string.char(0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15)
local function make_payload(size)
local out={}
for i=1,size do
out[i]=string.char((i*37+math.floor(i/251))%256)
end
return table.concat(out)
end
local function encrypt_test_payload(plaintext)
return cfb8.Stream.new(key):encrypt(plaintext)
end
local function decrypt_chunks_locally(ciphertext)
local chunk_count=math.ceil(#ciphertext/CHUNK_SIZE)
local results={}
for chunk_id=1,chunk_count do
local start_index=(chunk_id-1)*CHUNK_SIZE+1
local end_index=math.min(chunk_id*CHUNK_SIZE,#ciphertext)
local iv=start_index==1 and key or ciphertext:sub(start_index-16,start_index-1)
local chunk=ciphertext:sub(start_index,end_index)
local stream=cfb8.Stream.new(key,iv)
results[chunk_id]=stream:decrypt(chunk)
end
return table.concat(results),chunk_count
end
math.randomseed(os.time())
print("Local single-thread test: "..TEST_SIZE.." bytes")
local plaintext=make_payload(TEST_SIZE)
local ciphertext=encrypt_test_payload(plaintext)
local start=os.clock()
local decrypted,chunk_count=decrypt_chunks_locally(ciphertext)
local elapsed=os.clock()-start
print("chunks processed: "..chunk_count)
print(string.format("local decrypt time: %.3f sec",elapsed))
print("ciphertext size: "..#ciphertext.." bytes")
print("result: "..(decrypted==plaintext and"OK"or"FAIL"))
os.exit(decrypted==plaintext and 0 or 1)
