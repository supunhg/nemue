local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs service detection on open ports.
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
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Service Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  socket:set_timeout(3000)

  local probes = {
    {name = "HTTP", data = "GET / HTTP/1.0\r\n\r\n"},
    {name = "SMTP", data = "EHLO probe\r\n"},
    {name = "FTP", data = "\r\n"},
    {name = "SSH", data = "SSH-2.0-probe\r\n"}
  }

  for _, probe in ipairs(probes) do
    socket:send(probe.data)
    local response
    status, response = socket:receive()

    if status and response and #response > 0 then
      local banner = response:sub(1, 128)
      if banner:match("^HTTP/") then
        table.insert(result, "[+] Service: HTTP")
        break
      elseif banner:match("^220") then
        table.insert(result, "[+] Service: FTP/SMTP")
        break
      elseif banner:match("^SSH%-") then
        table.insert(result, "[+] Service: SSH")
        break
      end
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
