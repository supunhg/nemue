local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password auditing against Redis servers.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(6379, "redis")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  socket:send("AUTH test\r\n")
  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "Redis service detected")
    table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
    if response:match("NOAUTH") then
      table.insert(result, "Authentication required - brute force applicable")
    elseif response:match("OK") then
      table.insert(result, "No authentication required")
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
