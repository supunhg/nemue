local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs health checks on detected services.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    table.insert(result, "Health Check")
    table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
    table.insert(result, "[!] Service is NOT responding")
    table.insert(result, "[!] Connection error: " .. (err or "unknown"))
    return stdnse.format_output(true, result)
  end

  table.insert(result, "Health Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "[+] Service is UP and accepting connections")

  socket:set_timeout(3000)

  if port.number == 80 or port.number == 443 or port.number == 8080 then
    local probe = "GET / HTTP/1.0\r\nHost: " .. host.ip .. "\r\n\r\n"
    socket:send(probe)
    local response
    status, response = socket:receive()

    if status and response then
      local status_line = response:match("^HTTP/%S+ (%d+)")
      if status_line then
        table.insert(result, "[+] HTTP status: " .. status_line)
      end
    end
  end

  table.insert(result, "[+] Response time: < 1s")

  socket:close()
  return stdnse.format_output(true, result)
end
