local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Grabs service banners from open ports.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Banner Grab")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  socket:set_timeout(5000)

  local probe = "GET / HTTP/1.0\r\nHost: " .. host.ip .. "\r\n\r\n"
  socket:send(probe)

  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    local banner = response:sub(1, 512)
    table.insert(result, "[+] Banner received:")
    for line in banner:gmatch("[^\r\n]+") do
      table.insert(result, "    " .. line)
    end
  else
    table.insert(result, "[!] No banner received")
  end

  socket:close()
  return stdnse.format_output(true, result)
end
