local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts Zookeeper service information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(2181, "zookeeper")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  socket:send("srvr\r\n")
  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "Zookeeper Service Detected")
    table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
    table.insert(result, "Response: " .. response:sub(1, 80))
    port.version.name = "zookeeper"
    port.version.product = "Zookeeper"
    nmap.set_port_version(host, port)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
