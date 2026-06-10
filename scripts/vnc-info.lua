local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts information from a VNC server including protocol version and desktop name.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5900, "vnc")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "VNC Information:")
    if response:match("RFB") then
      local version = response:match("RFB (%d+%.%d+)")
      table.insert(result, "Protocol: RFB " .. (version or "unknown"))
    end
    table.insert(result, "Host: " .. host.ip)
    table.insert(result, "Port: " .. port.number)
    port.version.name = "vnc"
    port.version.product = "VNC"
    nmap.set_port_version(host, port)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
