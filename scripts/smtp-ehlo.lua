local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates SMTP capabilities using the EHLO command.
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

  local response
  status, response = socket:receive_lines(1)
  if not status then
    socket:close()
    return nil
  end

  socket:send("EHLO nmap.test\r\n")
  local capabilities = {}
  local line
  repeat
    status, line = socket:receive_lines(1)
    if status then
      local cap = line:match("^250[%-]%s*(.+)$")
      if cap then
        table.insert(capabilities, cap:gsub("\r?\n$", ""))
      end
    end
  until not status or (line and line:match("^250 "))

  socket:close()

  local output = stdnse.output_table()
  output["Capabilities"] = capabilities
  return output
end
