local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Queries the FTP SYST command to determine the operating system type.
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

  socket:send("SYST\r\n")
  status, response = socket:receive_lines(1)
  socket:close()

  if not status then
    return nil
  end

  local syst = response:gsub("\r?\n$", "")
  local os_type = syst:match("^215%s+(.+)$")

  local output = stdnse.output_table()
  output["SYST Response"] = syst
  output["OS Type"] = os_type or "Unknown"
  return output
end
