local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests for anonymous FTP access on the target server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return nil
  end

  local response
  status, response = socket:receive_lines(1)
  if not status then
    socket:close()
    return nil
  end

  socket:send("USER anonymous\r\n")
  status, response = socket:receive_lines(1)
  if not status then
    socket:close()
    return nil
  end

  socket:send("PASS anonymous@\r\n")
  status, response = socket:receive_lines(1)
  socket:close()

  if not status then
    return nil
  end

  local output = stdnse.output_table()
  if response:match("^230") then
    output["Anonymous Access"] = "Allowed"
    output["Status"] = "VULNERABLE"
  else
    output["Anonymous Access"] = "Denied"
    output["Status"] = "Secure"
  end
  return output
end
