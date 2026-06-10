local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects Telnet banner and authentication requirements.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(23, "telnet")

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
    table.insert(result, "Telnet Service Detection")
    table.insert(result, "Banner: " .. response:sub(1, 100):gsub("\r?\n$", ""))
    if response:match("[Ll]ogin") or response:match("[Uu]sername") then
      table.insert(result, "Authentication: Login required")
    end
    port.version.name = "telnet"
    nmap.set_port_version(host, port)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
