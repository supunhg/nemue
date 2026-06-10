local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for FTP encryption support (FTPS/TLS).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

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

  socket:send("AUTH TLS\r\n")
  status, response = socket:receive_lines(1)
  socket:close()

  local output = stdnse.output_table()
  if status and response:match("^234") then
    output["AUTH TLS"] = "Supported"
    output["Encryption"] = "Available"
  else
    output["AUTH TLS"] = "Not supported"
    output["Encryption"] = "Not available or plaintext only"
  end
  return output
end
