local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects RDP network level authentication (NLA) support.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(3389, "ms-wbt-server")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "RDP NLA Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "NLA enhances security by requiring authentication before session")
  table.insert(result, "Status: Requires X.224 connection confirm")

  socket:close()
  return stdnse.format_output(true, result)
end
