local component=require("component")
local computer=require("computer")
local shell=require("shell")
local fs=require("filesystem")
local _,opts=shell.parse(...)
local DRY=opts.dry and true or false
local FORCE=opts.force and true or false
local REPO=opts.repo or"Faticc/dwclient"
local BRANCH=opts.branch or"main"
local DIR=(opts.dir or"dist"):gsub("/+$","")
local SUB=DIR~=""and(DIR.."/")or""
local TO=(opts.to or"/home/dwclient"):gsub("/+$","")
if TO==""then TO="/"end
local STATE=TO.."/.dwclient"
local function die(s)io.stderr:write(s.."\n")os.exit(1)end
local last=computer.uptime()
local function breathe()
if computer.uptime()-last>1 then
last=computer.uptime()
os.sleep(0)
end
end
local crc32
do
local f=load([[
    local T = {}
    for i = 0, 255 do
      local c = i
      for _ = 1, 8 do
        if c & 1 == 1 then c = 0xEDB88320 ~ (c >> 1) else c = c >> 1 end
      end
      T[i] = c
    end
    local byte = string.byte
    return function(crc, s)
      crc = ~crc & 0xFFFFFFFF
      for i = 1, #s do crc = T[(crc ~ byte(s, i)) & 0xFF] ~ (crc >> 8) end
      return ~crc & 0xFFFFFFFF
    end]])
if f then
crc32=f()
elseif bit32 then
local band,bxor,rshift,bnot=bit32.band,bit32.bxor,bit32.rshift,bit32.bnot
local T={}
for i=0,255 do
local c=i
for _=1,8 do
if band(c,1)==1 then c=bxor(0xEDB88320,rshift(c,1))else c=rshift(c,1)end
end
T[i]=c
end
local byte=string.byte
crc32=function(crc,s)
crc=band(bnot(crc),0xFFFFFFFF)
for i=1,#s do
crc=bxor(T[band(bxor(crc,byte(s,i)),0xFF)],rshift(crc,8))
end
return band(bnot(crc),0xFFFFFFFF)
end
else
die("нет ни операторов Lua 5.3, ни bit32 -- не на чем считать CRC32")
end
end
local function hex(n)return string.format("%08x",n)end
local function file_crc(path)
local f=io.open(path,"rb")
if not f then return nil end
local crc,n=0,0
while true do
local chunk=f:read(4096)
if not chunk or#chunk==0 then break end
crc,n=crc32(crc,chunk),n+#chunk
breathe()
end
f:close()
return hex(crc),n
end
if not component.isAvailable("internet")then die("нужна интернет-карта")end
local internet=require("internet")
local function open_url(path)
local url=("https://raw.githubusercontent.com/%s/%s/%s%s"):format(REPO,BRANCH,SUB,path)
local ok,h=pcall(internet.request,url,nil,{["user-agent"]="dwclient"})
if not ok then return nil,tostring(h)end
local code
for _=1,200 do
code=h.response()
if code then break end
os.sleep(0.05)
end
if code and code~=200 then pcall(h.close)return nil,"HTTP "..code end
return h
end
local function fetch(path)
local h,why=open_url(path)
if not h then return nil,why end
local parts={}
local ok,err=pcall(function()
for chunk in h do parts[#parts+1]=chunk breathe()end
end)
pcall(h.close)
if not ok then return nil,tostring(err)end
return table.concat(parts)
end
local function mkdir(path)
local dir=path:match("^(.*)/[^/]*$")
if dir and dir~=""and not fs.exists(dir)then fs.makeDirectory(dir)end
end
local function download(path,to)
local h,why=open_url(path)
if not h then return nil,why end
mkdir(to)
local f,werr=io.open(to,"wb")
if not f then pcall(h.close)return nil,tostring(werr)end
local n,crc=0,0
local ok,err=pcall(function()
for chunk in h do
f:write(chunk)
n,crc=n+#chunk,crc32(crc,chunk)
breathe()
end
end)
f:close()
pcall(h.close)
if not ok then return nil,tostring(err)end
return n,hex(crc)
end
local function put(entry,to)
local part=to..".part"
local last_why
for try=1,2 do
local n,crc=download(entry[1],part)
if not n then
fs.remove(part)
last_why=crc
elseif(entry.size and n~=entry.size)or(entry.crc and crc~=entry.crc)then
fs.remove(part)
last_why=("пришло %d Б с хэшем %s, а ждали %s Б с хэшем %s")
:format(n,tostring(crc),tostring(entry.size),tostring(entry.crc))
else
if fs.exists(to)then fs.remove(to)end
local ok,rerr=fs.rename(part,to)
if not ok then fs.remove(part)return nil,"не переименовать .part: "..tostring(rerr)end
return n,crc
end
if try==1 then print("   повтор: "..tostring(last_why))end
end
return nil,last_why
end
local function read_state()
local f=io.open(STATE,"r")
if not f then return{}end
local src=f:read("*a")
f:close()
local chunk=load("return "..src,"=state","t",{})
local ok,t=pcall(chunk)
return(ok and type(t)=="table")and t or{}
end
local function write_state(state)
local lines={"{",("  repo = %q,"):format(REPO),("  branch = %q,"):format(BRANCH),
("  dir = %q,"):format(DIR),"  files = {"}
local names={}
for name in pairs(state.files or{})do names[#names+1]=name end
table.sort(names)
for _,name in ipairs(names)do
lines[#lines+1]=("    [%q] = %q,"):format(name,state.files[name])
end
lines[#lines+1]="  },"
lines[#lines+1]="}"
mkdir(STATE)
local f=io.open(STATE,"w")
if not f then return end
f:write(table.concat(lines,"\n").."\n")
f:close()
end
print(("dwclient: %s@%s/%s -> %s"):format(REPO,BRANCH,SUB~=""and SUB or".",TO))
local src,why=fetch("manifest.lua")
if not src then die("manifest.lua: "..tostring(why))end
local chunk,perr=load("return "..src,"=manifest","t",{})
if not chunk then die("manifest.lua не читается: "..tostring(perr))end
local manifest=chunk()
if type(manifest)~="table"or type(manifest.files)~="table"then
die("manifest.lua не похож на манифест")
end
local keep={}
for _,name in ipairs(manifest.keep or{})do keep[name]=true end
local state=read_state()
state.files=state.files or{}
local todo,unchanged,kept={},0,0
for _,entry in ipairs(manifest.files)do
local name=entry[1]
local target=TO.."/"..name
local have=fs.exists(target)
if keep[name]and have then
kept=kept+1
elseif FORCE or not have then
todo[#todo+1]=entry
else
local crc=state.files[name]
if crc~=entry.crc then crc=file_crc(target)end
if crc==entry.crc then
unchanged=unchanged+1
state.files[name]=crc
else
todo[#todo+1]=entry
end
end
end
print(("Сборка %s %s: %d файлов; обновить %d, совпадает %d, не трогаем %d")
:format(manifest.name or"dwclient",manifest.version or"",#manifest.files,
#todo,unchanged,kept))
if#todo==0 then
write_state(state)
print("Всё уже на месте.")
return
end
if DRY then
for _,entry in ipairs(todo)do
print(("   %s  %d Б"):format(entry[1],entry.size or 0))
end
return
end
local done=0
for _,entry in ipairs(todo)do
local target=TO.."/"..entry[1]
io.write(("[%d/%d] %s ... "):format(done+1,#todo,entry[1]))
local n,crc=put(entry,target)
if not n then
print("не вышло")
die("   "..entry[1]..": "..tostring(crc))
end
state.files[entry[1]]=crc
done=done+1
print(n.." Б")
write_state(state)
end
write_state(state)
print(("Готово: %d файлов в %s"):format(done,TO))
if not fs.exists(TO.."/hwid.lua")then
print("Дальше: положи рядом hwid.lua (его делает ghost_client/tools/make_hwid.py)")
print("и впиши сессию в начало main.lua.")
end
