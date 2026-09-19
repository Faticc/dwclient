local M={}
local gfx_ok,gfx=pcall(require,"gfx")
local unicode_ok,unicode=pcall(require,"unicode")
local ulen=unicode_ok and unicode.len or function(s)return#s end
local usub=unicode_ok and unicode.sub or string.sub
local COLOR_BG=0x000000
local COLOR_BAR=0x2D2D2D
local COLOR_BAR_TEXT=0xFFFFFF
local COLOR_ACCENT=0x55FFFF
local COLOR_DIM=0xAAAAAA
local COLOR_TEXT=0xCCCCCC
local COLOR_OK=0x55FF55
local COLOR_WARN=0xFFAA00
local computer=require("computer")
local Ui={}
Ui.__index=Ui
local function direct_surface(gpu)
local w,h=gpu.getResolution()
local fg,bg
return{
w=w,h=h,
set=function(self,x,y,s,f,b)
f,b=f or COLOR_TEXT,b or COLOR_BG
if f~=fg then gpu.setForeground(f);fg=f end
if b~=bg then gpu.setBackground(b);bg=b end
gpu.set(x,y,s)
end,
fill=function(self,x,y,fw,fh,ch,f,b)
f,b=f or COLOR_TEXT,b or COLOR_BG
if f~=fg then gpu.setForeground(f);fg=f end
if b~=bg then gpu.setBackground(b);bg=b end
gpu.fill(x,y,fw,fh,ch or" ")
end,
copy=function(self,x,y,cw,ch,tx,ty)gpu.copy(x,y,cw,ch,tx,ty)end,
present=function()end,
close=function()end,
}
end
function M.new(opts)
opts=opts or{}
local term_ok,term=pcall(require,"term")
if not term_ok then return nil end
local gpu_ok,gpu=pcall(function()return term.gpu()end)
if not gpu_ok or not gpu then return nil end
local surface
if gfx_ok then
local ok,s=pcall(gfx.surface,gpu)
surface=ok and s or nil
end
if not surface then surface=direct_surface(gpu)end
local self=setmetatable({
gpu=gpu,
s=surface,
w=surface.w,
h=surface.h,
title=opts.title or"ghost",
status_text="",
input_text="",
dirty=true,
clock=computer.uptime,
last_present=0,
input_drawn=0,
top=2,
bottom=surface.h-2,
},Ui)
self.rows=self.bottom-self.top+1
self.used=0
self.s:fill(1,1,self.w,self.h," ",COLOR_TEXT,COLOR_BG)
self:_draw_bar()
self:_draw_status()
self:_draw_input()
self:flush(true)
return self
end
function Ui:_draw_bar()
self.s:fill(1,1,self.w,1," ",COLOR_BAR_TEXT,COLOR_BAR)
self.s:set(2,1,usub(self.title,1,self.w-2),COLOR_BAR_TEXT,COLOR_BAR)
self.dirty=true
end
function Ui:_draw_status()
local y=self.h-1
self.s:fill(1,y,self.w,1," ",COLOR_DIM,COLOR_BG)
if self.status_text~=""then
self.s:set(2,y,usub(self.status_text,1,self.w-2),COLOR_DIM,COLOR_BG)
end
self.dirty=true
end
function Ui:_draw_input()
local y=self.h
local room=self.w-3
local text=self.input_text
if ulen(text)>room then text=usub(text,ulen(text)-room+1)end
local shown=ulen(text)
if text~=""then self.s:set(3,y,text,COLOR_BAR_TEXT,COLOR_BG)end
self.s:set(3+shown,y,"_",COLOR_ACCENT,COLOR_BG)
if self.input_drawn and self.input_drawn>shown then
self.s:fill(4+shown,y,self.input_drawn-shown,1," ",COLOR_ACCENT,COLOR_BG)
end
self.input_drawn=shown
self.dirty=true
end
function Ui:_scroll()
if self.used<self.rows then
self.used=self.used+1
return self.top+self.used-1
end
self.s:copy(1,self.top+1,self.w,self.rows-1,0,-1)
self.s:fill(1,self.bottom,self.w,1," ",COLOR_TEXT,COLOR_BG)
return self.bottom
end
local function wrap(segments,width)
local lines,line,used={},{},0
for i=1,#segments do
local seg=segments[i]
local text,color=seg.text,seg.color
while text~=""do
local room=width-used
if room<=0 then
lines[#lines+1]=line
line,used={},0
room=width
end
local take=ulen(text)
if take<=room then
line[#line+1]={text=text,color=color}
used=used+take
text=""
else
line[#line+1]={text=usub(text,1,room),color=color}
text=usub(text,room+1)
lines[#lines+1]=line
line,used={},0
end
end
end
if#line>0 then lines[#lines+1]=line end
if#lines==0 then lines[1]={{text="",color=nil}}end
return lines
end
function Ui:chat(segments)
local lines=wrap(segments,self.w-1)
for i=1,#lines do
local y=self:_scroll()
local x=1
local parts=lines[i]
for j=1,#parts do
local part=parts[j]
if part.text~=""then
self.s:set(x,y,part.text,part.color or COLOR_TEXT,COLOR_BG)
x=x+ulen(part.text)
end
end
end
self.dirty=true
end
function Ui:note(text,color)
self:chat({{text=text,color=color or COLOR_DIM}})
end
function Ui:status(text)
if text==self.status_text then return end
self.status_text=text
self:_draw_status()
end
function Ui:input(text)
if text==self.input_text then return end
self.input_text=text
self:_draw_input()
end
local PRESENT_INTERVAL=0.05
function Ui:flush(force)
if not self.dirty then return end
local now=self.clock()
if not force and(now-self.last_present)<PRESENT_INTERVAL then return end
self.last_present=now
self.s:present()
self.dirty=false
end
function Ui:close()
self.s:fill(1,1,self.w,self.h," ",COLOR_TEXT,COLOR_BG)
self.s:present()
if self.s.close then self.s:close()end
if self.gpu then
self.gpu.setForeground(0xFFFFFF)
self.gpu.setBackground(0x000000)
end
end
M.COLOR_OK=COLOR_OK
M.COLOR_WARN=COLOR_WARN
M.COLOR_DIM=COLOR_DIM
M.COLOR_ACCENT=COLOR_ACCENT
return M
