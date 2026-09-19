local aes=require("aes")
local bit=require("bit_compat")
local bxor=bit.bxor
local bor=bit.bor
local lshift32=bit.lshift32
local rshift32=bit.rshift32
local Stream={}
Stream.__index=Stream
local function bytes16_to_regs(bytes16)
local b0,b1,b2,b3=string.byte(bytes16,1,4)
local b4,b5,b6,b7=string.byte(bytes16,5,8)
local b8,b9,b10,b11=string.byte(bytes16,9,12)
local b12,b13,b14,b15=string.byte(bytes16,13,16)
return bit.from_bytes32(b0,b1,b2,b3),bit.from_bytes32(b4,b5,b6,b7),
bit.from_bytes32(b8,b9,b10,b11),bit.from_bytes32(b12,b13,b14,b15)
end
local function regs_to_bytes16(r0,r1,r2,r3)
local to_bytes=bit.to_bytes32
local a0,a1,a2,a3=to_bytes(r0)
local a4,a5,a6,a7=to_bytes(r1)
local a8,a9,a10,a11=to_bytes(r2)
local a12,a13,a14,a15=to_bytes(r3)
return string.char(a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15)
end
function Stream.new(shared_secret16,initial_register16)
assert(#shared_secret16==16,"shared secret must be 16 bytes")
initial_register16=initial_register16 or shared_secret16
assert(#initial_register16==16,"initial CFB8 register must be 16 bytes")
local r0,r1,r2,r3=bytes16_to_regs(initial_register16)
return setmetatable({
key16=shared_secret16,
rk=aes.expand_key(shared_secret16),
r0=r0,r1=r1,r2=r2,r3=r3,
},Stream)
end
local YIELD_EVERY=64
function Stream:_process(data,is_decrypt,yield_fn)
local out={}
local rk=self.rk
local keystream_byte=aes.keystream_byte
local char=string.char
local r0,r1,r2,r3=self.r0,self.r1,self.r2,self.r3
for i=1,#data do
local ks_byte=keystream_byte(rk,r0,r1,r2,r3)
local in_byte=string.byte(data,i)
local out_byte=bxor(in_byte,ks_byte)
local feedback_byte=is_decrypt and in_byte or out_byte
r0=bor(lshift32(r0,8),rshift32(r1,24))
r1=bor(lshift32(r1,8),rshift32(r2,24))
r2=bor(lshift32(r2,8),rshift32(r3,24))
r3=bor(lshift32(r3,8),feedback_byte)
out[i]=char(out_byte)
if yield_fn and i%YIELD_EVERY==0 then
self.r0,self.r1,self.r2,self.r3=r0,r1,r2,r3
yield_fn()
end
end
self.r0,self.r1,self.r2,self.r3=r0,r1,r2,r3
return table.concat(out)
end
function Stream:encrypt(plaintext,yield_fn)
return self:_process(plaintext,false,yield_fn)
end
function Stream:register()
return regs_to_bytes16(self.r0,self.r1,self.r2,self.r3)
end
function Stream:_advance_register(feedback)
local n=#feedback
local tail
if n>=16 then
tail=feedback:sub(n-15,n)
else
tail=self:register():sub(n+1,16)..feedback
end
self.r0,self.r1,self.r2,self.r3=bytes16_to_regs(tail)
end
function Stream:decrypt(ciphertext,yield_fn,cluster)
if cluster and cluster:available()and#ciphertext>=cluster.min_size then
local ok,result=pcall(cluster.decrypt,cluster,ciphertext,self.key16,self:register(),yield_fn)
if ok then
self:_advance_register(ciphertext)
return result
end
end
return self:_process(ciphertext,true,yield_fn)
end
return{Stream=Stream}
