local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if the SMTP server supports STARTTLS.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return nil
  end

  socket:receive_lines(1)
  socket:send("EHLO nmap.test\r\n")
  local line
  local starttls_cap = false
  repeat
    status, line = socket:receive_lines(1)
    if status and line:match("STARTTLS") then
      starttls_cap = true
    end
  until not status or (line and line:match("^250 "))

  socket:close()

  local output = stdnse.output_table()
  if starttls_cap then
    output["STARTTLS"] = "Supported"
    output["Encryption"] = "Available"
  else
    output["STARTTLS"] = "Not supported"
    output["Encryption"] = "Plaintext only"
    output["Recommendation"] = "Enable STARTTLS for encrypted communication"
  end
  return output
end
