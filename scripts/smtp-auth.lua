local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates SMTP authentication methods.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return nil
  end

  socket:receive_lines(1)
  socket:send("EHLO nmap.test\r\n")
  local line
  local auth_line = nil
  repeat
    status, line = socket:receive_lines(1)
    if status and line:match("AUTH ") then
      auth_line = line:gsub("\r?\n$", "")
    end
  until not status or (line and line:match("^250 "))

  socket:close()

  local output = stdnse.output_table()
  if auth_line then
    local methods = auth_line:match("^250[%-]AUTH%s+(.+)$") or auth_line:match("AUTH%s+(.+)$")
    output["AUTH Line"] = auth_line
    output["Auth Methods"] = methods or "Unknown"
  else
    output["Auth Methods"] = "None advertised"
  end
  return output
end
