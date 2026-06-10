local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates FTP features using the FEAT command.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

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

  socket:send("FEAT\r\n")
  local features = {}
  local line
  repeat
    status, line = socket:receive_lines(1)
    if status and not line:match("^211 ") and not line:match("^211%-") then
      table.insert(features, line:gsub("\r?\n$", ""):match("^%s*(.+)$") or "")
    end
  until not status or line:match("^211 ")

  socket:close()

  local output = stdnse.output_table()
  output["Features"] = features
  return output
end
