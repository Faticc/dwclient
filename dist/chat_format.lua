local M={}
local RESET="\27[0m"
local COLOR_CODES={
black="\27[30m",
dark_blue="\27[34m",
dark_green="\27[32m",
dark_aqua="\27[36m",
dark_red="\27[31m",
dark_purple="\27[35m",
gold="\27[33m",
gray="\27[37m",
dark_gray="\27[90m",
blue="\27[94m",
green="\27[92m",
aqua="\27[96m",
red="\27[91m",
light_purple="\27[95m",
yellow="\27[93m",
white="\27[97m",
}
local COLOR_HEX={
black=0x000000,
dark_blue=0x0000AA,
dark_green=0x00AA00,
dark_aqua=0x00AAAA,
dark_red=0xAA0000,
dark_purple=0xAA00AA,
gold=0xFFAA00,
gray=0xAAAAAA,
dark_gray=0x555555,
blue=0x5555FF,
green=0x55FF55,
aqua=0x55FFFF,
red=0xFF5555,
light_purple=0xFF55FF,
yellow=0xFFFF55,
white=0xFFFFFF,
}
local SECTION_SIGN="\194\167"
local LEGACY_COLOR_ANSI={
["0"]="\27[30m",["1"]="\27[34m",["2"]="\27[32m",["3"]="\27[36m",
["4"]="\27[31m",["5"]="\27[35m",["6"]="\27[33m",["7"]="\27[37m",
["8"]="\27[90m",["9"]="\27[94m",a="\27[92m",b="\27[96m",
c="\27[91m",d="\27[95m",e="\27[93m",f="\27[97m",
}
local LEGACY_FORMAT_ANSI={l="\27[1m",o="\27[3m",n="\27[4m",m="\27[9m",k=""}
local LEGACY_COLOR_HEX={
["0"]=0x000000,["1"]=0x0000AA,["2"]=0x00AA00,["3"]=0x00AAAA,
["4"]=0xAA0000,["5"]=0xAA00AA,["6"]=0xFFAA00,["7"]=0xAAAAAA,
["8"]=0x555555,["9"]=0x5555FF,a=0x55FF55,b=0x55FFFF,
c=0xFF5555,d=0xFF55FF,e=0xFFFF55,f=0xFFFFFF,
}
local ARRAY_MARKER={}
local function skip_ws(s,i)
local _,j=s:find("^[ \t\r\n]*",i)
return j+1
end
local decode_value
local function decode_string(s,i)
local j=i+1
local out={}
while true do
local c=s:sub(j,j)
if c==""then
error("unterminated JSON string")
elseif c=='"'then
return table.concat(out),j+1
elseif c=="\\"then
local esc=s:sub(j+1,j+1)
if esc=="u"then
local hex=s:sub(j+2,j+5)
local code=tonumber(hex,16)
if not code then error("bad \\u escape in JSON string")end
if code<0x80 then
out[#out+1]=string.char(code)
elseif code<0x800 then
out[#out+1]=string.char(0xC0+math.floor(code/0x40),0x80+(code%0x40))
else
out[#out+1]=string.char(
0xE0+math.floor(code/0x1000),
0x80+(math.floor(code/0x40)%0x40),
0x80+(code%0x40)
)
end
j=j+6
else
local map={['"']='"',["\\"]="\\",["/"]="/",b="\b",f="\f",n="\n",r="\r",t="\t"}
local rep=map[esc]
if not rep then error("bad escape \\"..esc.." in JSON string")end
out[#out+1]=rep
j=j+2
end
else
out[#out+1]=c
j=j+1
end
end
end
local function decode_array(s,i)
local arr={[ARRAY_MARKER]=true}
local j=skip_ws(s,i+1)
if s:sub(j,j)=="]"then
return arr,j+1
end
while true do
local val
val,j=decode_value(s,j)
arr[#arr+1]=val
j=skip_ws(s,j)
local c=s:sub(j,j)
if c=="]"then
return arr,j+1
elseif c~=","then
error("expected ',' or ']' in JSON array")
end
j=skip_ws(s,j+1)
end
end
local function decode_object(s,i)
local obj={}
local j=skip_ws(s,i+1)
if s:sub(j,j)=="}"then
return obj,j+1
end
while true do
if s:sub(j,j)~='"'then error("expected string key in JSON object")end
local key
key,j=decode_string(s,j)
j=skip_ws(s,j)
if s:sub(j,j)~=":"then error("expected ':' in JSON object")end
j=skip_ws(s,j+1)
local val
val,j=decode_value(s,j)
obj[key]=val
j=skip_ws(s,j)
local c=s:sub(j,j)
if c=="}"then
return obj,j+1
elseif c~=","then
error("expected ',' or '}' in JSON object")
end
j=skip_ws(s,j+1)
end
end
decode_value=function(s,i)
i=skip_ws(s,i)
local c=s:sub(i,i)
if c=='"'then
return decode_string(s,i)
elseif c=="{"then
return decode_object(s,i)
elseif c=="["then
return decode_array(s,i)
elseif s:sub(i,i+3)=="true"then
return true,i+4
elseif s:sub(i,i+4)=="false"then
return false,i+5
elseif s:sub(i,i+3)=="null"then
return nil,i+4
else
local numstr=s:match("^%-?%d+%.?%d*[eE]?[%+%-]?%d*",i)
if not numstr or numstr==""then
error("unexpected character in JSON at position "..i)
end
local n=tonumber(numstr)
if not n then error("bad JSON number")end
return n,i+#numstr
end
end
local function decode(s)
local val,j=decode_value(s,1)
j=skip_ws(s,j)
if j<=#s then
error("trailing data after JSON value")
end
return val
end
M.decode=decode
local function render_legacy_ansi(text)
if not text:find(SECTION_SIGN,1,true)then
return text
end
local pieces={}
local i=1
local n=#text
while i<=n do
if text:sub(i,i+1)==SECTION_SIGN and i+2<=n then
local code=text:sub(i+2,i+2):lower()
pieces[#pieces+1]=LEGACY_COLOR_ANSI[code]or LEGACY_FORMAT_ANSI[code]or(code=="r"and RESET)or""
i=i+3
else
pieces[#pieces+1]=text:sub(i,i)
i=i+1
end
end
pieces[#pieces+1]=RESET
return table.concat(pieces)
end
local function render_node(node,inherited_color)
local t=type(node)
if t=="string"then
return node
end
if t=="table"then
if node[ARRAY_MARKER]then
local pieces={}
for _,child in ipairs(node)do
pieces[#pieces+1]=render_node(child,inherited_color)
end
return table.concat(pieces)
end
local color=node.color or inherited_color
local code=(color and COLOR_CODES[color])or""
local pieces={}
local text=node.text
if text and text~=""then
text=render_legacy_ansi(text)
pieces[#pieces+1]=(code~=""and(code..text..RESET))or text
end
if node.extra then
for _,extra in ipairs(node.extra)do
pieces[#pieces+1]=render_node(extra,color)
end
end
return table.concat(pieces)
end
return""
end
function M.render_chat_json(raw)
local ok,data=pcall(decode,raw)
if not ok then
return render_legacy_ansi(raw)
end
local ok2,result=pcall(render_node,data,nil)
if not ok2 then
return render_legacy_ansi(raw)
end
return result
end
local function split_legacy(text,color,out)
if not text:find(SECTION_SIGN,1,true)then
if text~=""then out[#out+1]={text=text,color=color}end
return
end
local buf={}
local function flush()
if#buf>0 then
out[#out+1]={text=table.concat(buf),color=color}
buf={}
end
end
local i=1
local n=#text
while i<=n do
if text:sub(i,i+1)==SECTION_SIGN and i+2<=n then
flush()
local code=text:sub(i+2,i+2):lower()
if LEGACY_COLOR_HEX[code]then
color=LEGACY_COLOR_HEX[code]
elseif code=="r"then
color=nil
end
i=i+3
else
buf[#buf+1]=text:sub(i,i)
i=i+1
end
end
flush()
end
local function render_node_segments(node,inherited_color,out)
local t=type(node)
if t=="string"then
split_legacy(node,inherited_color,out)
return
end
if t=="table"then
if node[ARRAY_MARKER]then
for _,child in ipairs(node)do
render_node_segments(child,inherited_color,out)
end
return
end
local color=inherited_color
if node.color and COLOR_HEX[node.color]then
color=COLOR_HEX[node.color]
end
local text=node.text
if text and text~=""then
split_legacy(text,color,out)
end
if node.extra then
for _,extra in ipairs(node.extra)do
render_node_segments(extra,color,out)
end
end
end
end
function M.render_chat_segments(raw)
local ok,data=pcall(decode,raw)
if not ok then
local out={}
local split_ok=pcall(split_legacy,raw,nil,out)
if split_ok and#out>0 then
return out
end
return{{text=raw,color=nil}}
end
local out={}
local ok2=pcall(render_node_segments,data,nil,out)
if not ok2 or#out==0 then
return{{text=raw,color=nil}}
end
return out
end
return M
