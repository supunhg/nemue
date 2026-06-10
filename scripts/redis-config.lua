local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks Redis configuration for security issues.
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

  socket:send("CONFIG GET requirepass\r\n")
  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "Redis Configuration Check")
    if response:match("ERR") then
      table.insert(result, "Authentication required")
    else
      table.insert(result, "No authentication configured (WARNING)")
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
