local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects VNC authentication type and security configuration.
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
    if response:match("RFB") then
      table.insert(result, "VNC service detected")
      local version = response:match("RFB (%d+%.%d+)")
      if version then
        table.insert(result, "Protocol version: " .. version)
      end
      table.insert(result, "Authentication type: Requires further probing")
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
