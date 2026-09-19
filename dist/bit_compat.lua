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
