local M={}
local sink_line,sink_status
local clock
local started,last_step
local function now()
if clock then return clock()end
local ok,computer=pcall(require,"computer")
clock=(ok and computer.uptime)or os.clock
return clock()
end
function M.init(line_fn,status_fn)
sink_line,sink_status=line_fn,status_fn
started=now()
last_step=started
end
function M.enabled()
return sink_line~=nil or sink_status~=nil
end
function M.step(text)
if not sink_line then return end
local t=now()
local since=t-(last_step or t)
last_step=t
if since>=0.1 then
sink_line(string.format("%5.1fs +%.1f  %s",t-started,since,text))
else
sink_line(string.format("%5.1fs        %s",t-started,text))
end
end
local busy_text,busy_since
function M.busy(text)
busy_text,busy_since=text,now()
if sink_status then sink_status(text.." ...")end
end
function M.progress(done,total)
if not sink_status or not busy_text then return end
local elapsed=now()-(busy_since or now())
if done and total and total>0 then
sink_status(string.format("%s: %d%% (%d из %d Б, %.0f с)",
busy_text,math.floor(done*100/total),done,total,elapsed))
else
sink_status(string.format("%s: идёт %.0f с",busy_text,elapsed))
end
end
function M.done(text)
if busy_text then
local elapsed=now()-(busy_since or now())
if elapsed>=0.5 then
M.step(string.format("%s -- %.1f с",text or busy_text,elapsed))
end
busy_text,busy_since=nil,nil
end
if sink_status then sink_status("")end
end
function M.elapsed()
return now()-(started or now())
end
return M
