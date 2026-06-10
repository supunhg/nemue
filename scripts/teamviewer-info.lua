local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects TeamViewer service and version.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5938, "teamviewer")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "TeamViewer Service Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: TeamViewer")
  table.insert(result, "Default port: 5938/TCP")
  table.insert(result, "Security: Check for unauthorized remote access")
  port.version.name = "teamviewer"
  port.version.product = "TeamViewer"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
