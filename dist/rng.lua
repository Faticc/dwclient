local ok,component=pcall(require,"component")
local has_data_card=ok and component.isAvailable and component.isAvailable("data")
local M={using_data_card=has_data_card}
if has_data_card then
function M.random_bytes(n)
return component.data.random(n)
end
else
math.randomseed(os.time()+(os.clock()*1000000))
function M.random_bytes(n)
local out={}
for i=1,n do
out[i]=string.char(math.random(0,255))
end
return table.concat(out)
end
end
function M.random_byte()
return string.byte(M.random_bytes(1))
end
return M
