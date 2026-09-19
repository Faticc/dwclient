local M={}
local BASE=65536
local floor=math.floor
local function copy(a)
local out={}
for i=1,#a do out[i]=a[i]end
return out
end
local function normalize(a)
local n=#a
while n>1 and a[n]==0 do
n=n-1
end
local out={}
for i=1,n do out[i]=a[i]end
return out
end
M.normalize=normalize
function M.from_bytes(bytes)
local limbs={0}
for i=1,#bytes do
local carry=string.byte(bytes,i)
for j=1,#limbs do
local v=limbs[j]*256+carry
limbs[j]=v%BASE
carry=floor(v/BASE)
end
while carry>0 do
limbs[#limbs+1]=carry%BASE
carry=floor(carry/BASE)
end
end
return normalize(limbs)
end
function M.from_int(n)
local limbs={}
if n==0 then return{0}end
while n>0 do
limbs[#limbs+1]=n%BASE
n=floor(n/BASE)
end
return limbs
end
function M.to_bytes(a,min_len)
a=normalize(a)
local out={}
local limbs=copy(a)
while not(#limbs==1 and limbs[1]==0)do
local rem=0
for i=#limbs,1,-1 do
local cur=rem*BASE+limbs[i]
limbs[i]=floor(cur/256)
rem=cur%256
end
limbs=normalize(limbs)
out[#out+1]=rem
end
while#out<(min_len or 0)do
out[#out+1]=0
end
local chars={}
for i=#out,1,-1 do
chars[#chars+1]=string.char(out[i])
end
if#chars==0 then chars={string.char(0)}end
return table.concat(chars)
end
function M.compare(a,b)
a,b=normalize(a),normalize(b)
if#a~=#b then return(#a<#b)and-1 or 1 end
for i=#a,1,-1 do
if a[i]~=b[i]then return(a[i]<b[i])and-1 or 1 end
end
return 0
end
function M.is_zero(a)
a=normalize(a)
return#a==1 and a[1]==0
end
function M.add(a,b)
local out={}
local carry=0
local n=math.max(#a,#b)
for i=1,n do
local v=(a[i]or 0)+(b[i]or 0)+carry
out[i]=v%BASE
carry=floor(v/BASE)
end
if carry>0 then out[n+1]=carry end
return normalize(out)
end
function M.sub(a,b)
local out={}
local borrow=0
for i=1,#a do
local v=a[i]-(b[i]or 0)-borrow
if v<0 then
v=v+BASE
borrow=1
else
borrow=0
end
out[i]=v
end
return normalize(out)
end
local function shl1(a)
local out={}
local carry=0
for i=1,#a do
local v=a[i]*2+carry
out[i]=v%BASE
carry=floor(v/BASE)
end
if carry>0 then out[#a+1]=carry end
return out
end
M.shl1=shl1
local function shr1(a)
local out={}
local carry=0
for i=#a,1,-1 do
local v=carry*BASE+a[i]
out[i]=floor(v/2)
carry=v%2
end
return normalize(out)
end
M.shr1=shr1
local function is_odd(a)
return a[1]%2==1
end
function M.mul(a,b)
local out={}
for i=1,#a+#b do out[i]=0 end
for i=1,#a do
local ai=a[i]
if ai~=0 then
for j=1,#b do
out[i+j-1]=out[i+j-1]+ai*b[j]
end
end
end
local carry=0
for i=1,#out do
local v=out[i]+carry
out[i]=v%BASE
carry=floor(v/BASE)
end
while carry>0 do
out[#out+1]=carry%BASE
carry=floor(carry/BASE)
end
return normalize(out)
end
function M.divmod(a,b,yield_fn)
assert(not M.is_zero(b),"division by zero")
a=normalize(a)
if M.compare(a,b)<0 then
return M.from_int(0),a
end
local shifted=copy(b)
local shift_count=0
while M.compare(shl1(shifted),a)<=0 do
shifted=shl1(shifted)
shift_count=shift_count+1
end
local remainder=a
local quotient=M.from_int(0)
for i=shift_count,0,-1 do
quotient=shl1(quotient)
if M.compare(remainder,shifted)>=0 then
remainder=M.sub(remainder,shifted)
quotient[1]=quotient[1]+1
end
shifted=shr1(shifted)
if yield_fn and i%64==0 then yield_fn()end
end
return normalize(quotient),normalize(remainder)
end
function M.mod(a,m,yield_fn)
local _,r=M.divmod(a,m,yield_fn)
return r
end
function M.modexp(base,exp,m,yield_fn)
base=M.mod(base,m,yield_fn)
local result=M.from_int(1)
exp=normalize(exp)
local bits={}
local e=copy(exp)
while not M.is_zero(e)do
bits[#bits+1]=e[1]%2
e=shr1(e)
end
for i=#bits,1,-1 do
result=M.mod(M.mul(result,result),m,yield_fn)
if bits[i]==1 then
result=M.mod(M.mul(result,base),m,yield_fn)
end
if yield_fn then yield_fn()end
end
return result
end
return M
