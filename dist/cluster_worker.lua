local component=require("component")
local event=require("event")
local cfb8=require("cfb8")
local modem=component.modem
local PORT=1234
local COMMAND="ghost-cfb8-decrypt"
modem.open(PORT)
print("CFB8 worker ready on port "..PORT)
while true do
local _,_,sender,port,_,command,request_id,chunk_id,key,iv,ciphertext=event.pull("modem_message")
if port==PORT and command==COMMAND then
local ok,plaintext=pcall(function()
return cfb8.Stream.new(key,iv):decrypt(ciphertext)
end)
if ok then
modem.send(sender,PORT,COMMAND.."-result",request_id,chunk_id,plaintext)
else
modem.send(sender,PORT,COMMAND.."-error",request_id,chunk_id,tostring(plaintext))
end
end
end
