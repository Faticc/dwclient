local bit=require("bit_compat")
local band,bxor,bnot,rotl32,add32=bit.band,bit.bxor,bit.bnot,bit.rotl32,bit.add32
local pow2=bit.pow2
local unpack=table.unpack or unpack
local floor=math.floor
local function bor(a,b)return bit.bor(a,b)end
local function sha1(message)
local msg_len=#message
local bit_len=msg_len*8
local padded={message,string.char(0x80)}
local pad_zeros=(56-(msg_len+1)%64)%64
padded[#padded+1]=string.rep("\0",pad_zeros)
local len_bytes={}
local v=bit_len
for i=8,1,-1 do
len_bytes[i]=v%256
v=floor(v/256)
end
padded[#padded+1]=string.char(unpack(len_bytes))
local data=table.concat(padded)
local h0,h1,h2,h3,h4=0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0
local w={}
for chunk_start=1,#data,64 do
for i=0,15 do
local o=chunk_start+i*4
local b0,b1,b2,b3=string.byte(data,o,o+3)
w[i]=((b0*256+b1)*256+b2)*256+b3
end
for i=16,79 do
w[i]=rotl32(bxor(bxor(w[i-3],w[i-8]),bxor(w[i-14],w[i-16])),1)
end
local a,b,c,d,e=h0,h1,h2,h3,h4
for i=0,79 do
local f,k
if i<20 then
f=bor(band(b,c),band(bnot(b)%pow2[32],d))
k=0x5A827999
elseif i<40 then
f=bxor(bxor(b,c),d)
k=0x6ED9EBA1
elseif i<60 then
f=bor(bor(band(b,c),band(b,d)),band(c,d))
k=0x8F1BBCDC
else
f=bxor(bxor(b,c),d)
k=0xCA62C1D6
end
local temp=add32(rotl32(a,5),f,e,k,w[i])
e=d
d=c
c=rotl32(b,30)
b=a
a=temp
end
h0=add32(h0,a)
h1=add32(h1,b)
h2=add32(h2,c)
h3=add32(h3,d)
h4=add32(h4,e)
end
local function word_to_bytes(v)
local b0,b1,b2,b3=bit.to_bytes32(v)
return string.char(b0,b1,b2,b3)
end
return word_to_bytes(h0)..word_to_bytes(h1)..word_to_bytes(h2)..word_to_bytes(h3)..word_to_bytes(h4)
end
local function to_hex(bytes)
local out={}
for i=1,#bytes do
out[i]=string.format("%02x",string.byte(bytes,i))
end
return table.concat(out)
end
return{hash=sha1,to_hex=to_hex}
