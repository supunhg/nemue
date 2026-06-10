local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts RTSP (streaming) service information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(554, "rtsp")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "RTSP Service Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: RTSP (Streaming)")
  table.insert(result, "Default port: 554/TCP")
  port.version.name = "rtsp"
  port.version.product = "RTSP"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
