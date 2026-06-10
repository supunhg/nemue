local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if the FTP server is vulnerable to bounce attacks (PORT command).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

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
  if not status then
    socket:close()
    return nil
  end

  socket:send("PORT 127,0,0,1,0,25\r\n")
  status, response = socket:receive_lines(1)
  socket:close()

  local output = stdnse.output_table()
  if status and response:match("^200") then
    output["Bounce Attack"] = "VULNERABLE"
    output["Severity"] = "Medium"
    output["Recommendation"] = "Disable PORT command for non-standard addresses"
  else
    output["Bounce Attack"] = "Not vulnerable"
  end
  return output
end
