local bn=require("bignum")
local function read_length(der,pos)
local first=string.byte(der,pos)
pos=pos+1
if first<0x80 then
return first,pos
end
local num_bytes=first-0x80
local length=0
for _=1,num_bytes do
length=length*256+string.byte(der,pos)
pos=pos+1
end
return length,pos
end
local function read_tlv(der,pos)
local tag=string.byte(der,pos)
pos=pos+1
local length,value_start=read_length(der,pos)
local value=der:sub(value_start,value_start+length-1)
return tag,value,value_start+length
end
local TAG_SEQUENCE=0x30
local TAG_INTEGER=0x02
local TAG_BIT_STRING=0x03
local function strip_der_integer_padding(bytes)
if#bytes>1 and string.byte(bytes,1)==0x00 then
return bytes:sub(2)
end
return bytes
end
local function parse_public_key(der_bytes)
local outer_tag,outer_value=read_tlv(der_bytes,1)
assert(outer_tag==TAG_SEQUENCE,"expected outer SEQUENCE")
local pos=1
local _alg_tag,_alg_value,next_pos=read_tlv(outer_value,pos)
pos=next_pos
local bitstring_tag,bitstring_value=read_tlv(outer_value,pos)
assert(bitstring_tag==TAG_BIT_STRING,"expected BIT STRING")
local rsa_key_der=bitstring_value:sub(2)
local inner_tag,inner_value=read_tlv(rsa_key_der,1)
assert(inner_tag==TAG_SEQUENCE,"expected inner RSAPublicKey SEQUENCE")
local ipos=1
local n_tag,n_bytes,n_next=read_tlv(inner_value,ipos)
assert(n_tag==TAG_INTEGER,"expected modulus INTEGER")
local e_tag,e_bytes=read_tlv(inner_value,n_next)
assert(e_tag==TAG_INTEGER,"expected exponent INTEGER")
n_bytes=strip_der_integer_padding(n_bytes)
e_bytes=strip_der_integer_padding(e_bytes)
return bn.from_bytes(n_bytes),bn.from_bytes(e_bytes),#n_bytes
end
local function pkcs1_pad(data,modulus_byte_length,random_byte)
local pad_len=modulus_byte_length-3-#data
assert(pad_len>=8,"message too long for this RSA key size")
local padding={}
for i=1,pad_len do
local b
repeat
b=random_byte()
until b~=0
padding[i]=string.char(b)
end
return"\0\2"..table.concat(padding).."\0"..data
end
local function encrypt(n,e,modulus_byte_length,plaintext,random_byte,yield_fn)
local padded=pkcs1_pad(plaintext,modulus_byte_length,random_byte)
local m=bn.from_bytes(padded)
local c=bn.modexp(m,e,n,yield_fn)
return bn.to_bytes(c,modulus_byte_length)
end
return{
parse_public_key=parse_public_key,
encrypt=encrypt,
}
