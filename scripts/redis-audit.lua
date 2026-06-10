local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs a Redis security audit checking configuration and exposure.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(6379, "redis")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  socket:send("INFO\r\n")
  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "Redis service detected")
    table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
    if response:match("redis_version") then
      local ver = response:match("redis_version:(%S+)")
      if ver then
        table.insert(result, "Version: " .. ver)
      end
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
