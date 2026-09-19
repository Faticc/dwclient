local bit_compat=(function()
local M={}
local floor=math.floor
local pow2={}
do
local v=1
for i=0,32 do
pow2[i]=v
v=v*2
end
end
M.pow2=pow2
local function to_bytes(x)
local b3=x%256;x=floor(x/256)
local b2=x%256;x=floor(x/256)
local b1=x%256;x=floor(x/256)
local b0=x%256
return b0,b1,b2,b3
end
M.to_bytes32=to_bytes
local function from_bytes(b0,b1,b2,b3)
return((b0*256+b1)*256+b2)*256+b3
end
M.from_bytes32=from_bytes
local function detect_native()
local ok,band,bor,bxor,bnot,lshift,rshift,rotl,to_bytes32,from_bytes32=pcall(function()
local chunk=load([[
            local function to_bytes32(x)
                return (x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, x & 0xff
            end
            local function from_bytes32(b0, b1, b2, b3)
                return ((b0 << 24) | (b1 << 16) | (b2 << 8) | b3) & 0xffffffff
            end
            local function rotl(x, n)
                n = n % 32
                if n == 0 then return x & 0xffffffff end
                return ((x << n) | (x >> (32 - n))) & 0xffffffff
            end
            return
                function(a, b) return (a & b) & 0xffffffff end,
                function(a, b) return (a | b) & 0xffffffff end,
                function(a, b) return (a ~ b) & 0xffffffff end,
                function(a) return (~a) & 0xffffffff end,
                function(a, n) return (a << n) & 0xffffffff end,
                function(a, n) return (a >> n) & 0xffffffff end,
                rotl, to_bytes32, from_bytes32
        ]])
return chunk()
end)
if ok and bxor(0xff00ff00,0x0f0f0f0f)==0xf00ff00f
and lshift(0x000000ff,24)==0xff000000 and rshift(0xff00ff00,8)==0x00ff00ff then
return band,bor,bxor,bnot,lshift,rshift,"native operators",rotl,to_bytes32,from_bytes32
end
if bit32 and bit32.bxor(0xff00ff00,0x0f0f0f0f)==0xf00ff00f then
return bit32.band,bit32.bor,bit32.bxor,bit32.bnot,bit32.lshift,bit32.rshift,"bit32"
end
local req_ok,bitlib=pcall(require,"bit")
if req_ok and bitlib then
local function u32(v)if v<0 then v=v+4294967296 end return v end
local nband=function(a,b)return u32(bitlib.band(a,b))end
local nbor=function(a,b)return u32(bitlib.bor(a,b))end
local nbxor=function(a,b)return u32(bitlib.bxor(a,b))end
local nbnot=function(a)return u32(bitlib.bnot(a))end
local nlshift=function(a,n)return u32(bitlib.lshift(a,n))end
local nrshift=function(a,n)return u32(bitlib.rshift(a,n))end
if nbxor(0xff00ff00,0x0f0f0f0f)==0xf00ff00f then
return nband,nbor,nbxor,nbnot,nlshift,nrshift,"LuaJIT bit"
end
end
return nil
end
local nband,nbor,nbxor,nbnot,nlshift,nrshift,backend_name,nrotl,nto_bytes32,nfrom_bytes32=detect_native()
M.backend=backend_name or"byte-table"
if nband then
M.band,M.bor,M.bxor,M.bnot=nband,nbor,nbxor,nbnot
M.lshift32=nlshift
M.rshift32=nrshift
if nrotl then
M.rotl32,M.to_bytes32,M.from_bytes32=nrotl,nto_bytes32,nfrom_bytes32
else
function M.rotl32(x,n)
n=n%32
if n==0 then return nband(x,0xffffffff)end
return nbor(nlshift(x,n),nrshift(x,32-n))
end
function M.to_bytes32(x)
return nrshift(x,24),nband(nrshift(x,16),0xff),nband(nrshift(x,8),0xff),nband(x,0xff)
end
function M.from_bytes32(b0,b1,b2,b3)
return nbor(nbor(nlshift(b0,24),nlshift(b1,16)),nbor(nlshift(b2,8),b3))
end
end
else
local BAND,BOR,BXOR={},{},{}
for a=0,255 do
BAND[a],BOR[a],BXOR[a]={},{},{}
for b=0,255 do
local band_ab,bor_ab,bxor_ab=0,0,0
local aa,bb,bit=a,b,1
for _=1,8 do
local abit=aa%2
local bbit=bb%2
if abit==1 and bbit==1 then band_ab=band_ab+bit end
if abit==1 or bbit==1 then bor_ab=bor_ab+bit end
if abit~=bbit then bxor_ab=bxor_ab+bit end
aa=floor(aa/2)
bb=floor(bb/2)
bit=bit*2
end
BAND[a][b]=band_ab
BOR[a][b]=bor_ab
BXOR[a][b]=bxor_ab
end
end
local function byteop(tbl,x,y)
local xa,xb,xc,xd=to_bytes(x)
local ya,yb,yc,yd=to_bytes(y)
return from_bytes(tbl[xa][ya],tbl[xb][yb],tbl[xc][yc],tbl[xd][yd])
end
function M.band(x,y)return byteop(BAND,x,y)end
function M.bor(x,y)return byteop(BOR,x,y)end
function M.bxor(x,y)return byteop(BXOR,x,y)end
function M.bnot(x)
return 4294967295-x
end
end
if not M.lshift32 then
function M.lshift32(x,n)
if n<=0 then return x%pow2[32]end
if n>=32 then return 0 end
return(x%pow2[32-n])*pow2[n]
end
function M.rshift32(x,n)
if n<=0 then return x%pow2[32]end
if n>=32 then return 0 end
return floor(x/pow2[n])
end
function M.rotl32(x,n)
n=n%32
if n==0 then return x%pow2[32]end
local high=floor(x/pow2[32-n])
local low=x-high*pow2[32-n]
return low*pow2[n]+high
end
end
function M.add32(...)
local s=0
for _,v in ipairs({...})do
s=s+v
end
return s%pow2[32]
end
return M
end)()
local aes=(function()
local bit=bit_compat
local bxor,band,rotl32=bit.band and bit.bxor,bit.band,bit.rotl32
bxor=bit.bxor
local to_bytes32,from_bytes32=bit.to_bytes32,bit.from_bytes32
local floor=math.floor
local SBOX={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
}
local RCON={0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36}
local function xtime(x)
local shifted=x*2
if x>=0x80 then
return bxor(shifted%256,0x1b)
end
return shifted
end
local function gmul(a,b)
local p=0
for _=1,8 do
if b%2==1 then p=bxor(p,a)end
a=xtime(a)
b=floor(b/2)
end
return p
end
local Te0,Te1,Te2,Te3={},{},{},{}
for x=0,255 do
local s=SBOX[x+1]
local s2=gmul(s,2)
local s3=gmul(s,3)
local w=from_bytes32(s2,s,s,s3)
Te0[x]=w
Te1[x]=bit.rotl32(w,24)
Te2[x]=bit.rotl32(w,16)
Te3[x]=bit.rotl32(w,8)
end
local function sb(x)return SBOX[x+1]end
local function sub_word(w)
local b0,b1,b2,b3=to_bytes32(w)
return from_bytes32(SBOX[b0+1],SBOX[b1+1],SBOX[b2+1],SBOX[b3+1])
end
local function expand_key(key16)
assert(#key16==16,"AES-128 key must be 16 bytes")
local w={}
for i=0,3 do
local o=i*4+1
local b0,b1,b2,b3=string.byte(key16,o,o+3)
w[i]=from_bytes32(b0,b1,b2,b3)
end
for i=4,43 do
local temp=w[i-1]
if i%4==0 then
temp=bit.rotl32(temp,8)
temp=sub_word(temp)
temp=bxor(temp,RCON[i/4]*0x1000000)
end
w[i]=bxor(w[i-4],temp)
end
return w
end
local function _rounds(rk,s0,s1,s2,s3)
for round=1,9 do
local ridx=round*4
local rk0,rk1,rk2,rk3=rk[ridx],rk[ridx+1],rk[ridx+2],rk[ridx+3]
local a0,a1,a2,a3=to_bytes32(s0)
local c0,c1,c2,c3=to_bytes32(s1)
local d0,d1,d2,d3=to_bytes32(s2)
local e0,e1,e2,e3=to_bytes32(s3)
local n0=bxor(bxor(bxor(Te0[a0],Te1[c1]),bxor(Te2[d2],Te3[e3])),rk0)
local n1=bxor(bxor(bxor(Te0[c0],Te1[d1]),bxor(Te2[e2],Te3[a3])),rk1)
local n2=bxor(bxor(bxor(Te0[d0],Te1[e1]),bxor(Te2[a2],Te3[c3])),rk2)
local n3=bxor(bxor(bxor(Te0[e0],Te1[a1]),bxor(Te2[c2],Te3[d3])),rk3)
s0,s1,s2,s3=n0,n1,n2,n3
end
return s0,s1,s2,s3
end
local function keystream_byte(rk,r0,r1,r2,r3)
local s0,s1,s2,s3=_rounds(rk,bxor(r0,rk[0]),bxor(r1,rk[1]),bxor(r2,rk[2]),bxor(r3,rk[3]))
local a0=to_bytes32(s0)
local _,c1=to_bytes32(s1)
local _,_,d2=to_bytes32(s2)
local _,_,_,e3=to_bytes32(s3)
return floor(bxor(from_bytes32(sb(a0),sb(c1),sb(d2),sb(e3)),rk[40])/16777216)
end
local function encrypt_block(rk,block16)
local b0,b1,b2,b3=string.byte(block16,1,4)
local b4,b5,b6,b7=string.byte(block16,5,8)
local b8,b9,b10,b11=string.byte(block16,9,12)
local b12,b13,b14,b15=string.byte(block16,13,16)
local r0=from_bytes32(b0,b1,b2,b3)
local r1=from_bytes32(b4,b5,b6,b7)
local r2=from_bytes32(b8,b9,b10,b11)
local r3=from_bytes32(b12,b13,b14,b15)
local s0,s1,s2,s3=_rounds(rk,bxor(r0,rk[0]),bxor(r1,rk[1]),bxor(r2,rk[2]),bxor(r3,rk[3]))
local a0,a1,a2,a3=to_bytes32(s0)
local c0,c1,c2,c3=to_bytes32(s1)
local d0,d1,d2,d3=to_bytes32(s2)
local e0,e1,e2,e3=to_bytes32(s3)
local f0=bxor(from_bytes32(sb(a0),sb(c1),sb(d2),sb(e3)),rk[40])
local f1=bxor(from_bytes32(sb(c0),sb(d1),sb(e2),sb(a3)),rk[41])
local f2=bxor(from_bytes32(sb(d0),sb(e1),sb(a2),sb(c3)),rk[42])
local f3=bxor(from_bytes32(sb(e0),sb(a1),sb(c2),sb(d3)),rk[43])
local o0,o1,o2,o3=to_bytes32(f0)
local o4,o5,o6,o7=to_bytes32(f1)
local o8,o9,o10,o11=to_bytes32(f2)
local o12,o13,o14,o15=to_bytes32(f3)
return string.char(o0,o1,o2,o3,o4,o5,o6,o7,o8,o9,o10,o11,o12,o13,o14,o15)
end
return{
expand_key=expand_key,
encrypt_block=encrypt_block,
keystream_byte=keystream_byte,
}
end)()
local cfb8=(function()
local aes=aes
local bit=bit_compat
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
end)()
local component=require("component")
local event=require("event")
local tunnel=component.tunnel
if not tunnel then
error("no Linked Card (tunnel component) found on this computer")
end
local COMMAND="ghost-cfb8-decrypt"
print("CFB8 tunnel worker ready")
while true do
local _,_,_,_,_,command,request_id,chunk_id,key,iv,ciphertext=event.pull("modem_message")
if command==COMMAND then
local ok,plaintext=pcall(function()
return cfb8.Stream.new(key,iv):decrypt(ciphertext)
end)
if ok then
tunnel.send(COMMAND.."-result",request_id,chunk_id,plaintext)
else
tunnel.send(COMMAND.."-error",request_id,chunk_id,tostring(plaintext))
end
end
end
