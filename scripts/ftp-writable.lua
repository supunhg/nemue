local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if anonymous users can write to FTP directories.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

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
  socket:receive_lines(1)
  socket:send("PASS anonymous@\r\n")
  status, response = socket:receive_lines(1)
  if not status or not response:match("^230") then
    socket:close()
    return nil
  end

  socket:send("MKD /nmap_test_dir\r\n")
  status, response = socket:receive_lines(1)

  if status and response:match("^257") then
    socket:send("RMD /nmap_test_dir\r\n")
    socket:receive_lines(1)
  end

  socket:close()

  local output = stdnse.output_table()
  if status and response:match("^257") then
    output["Writable Directory"] = "VULNERABLE"
    output["Severity"] = "High"
  else
    output["Writable Directory"] = "Not writable"
  end
  return output
end
