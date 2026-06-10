local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if the SMTP server is an open relay.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "vuln"}

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
  repeat
    status, line = socket:receive_lines(1)
  until not status or (line and line:match("^250 "))

  socket:send("MAIL FROM:<test@external.com>\r\n")
  status, line = socket:receive_lines(1)
  local mail_from_ok = status and line:match("^250")

  if not mail_from_ok then
    socket:close()
    local output = stdnse.output_table()
    output["Open Relay"] = "No (MAIL FROM rejected)"
    return output
  end

  socket:send("RCPT TO:<test@external.com>\r\n")
  status, line = socket:receive_lines(1)
  local rcpt_ok = status and (line:match("^250") or line:match("^251"))

  socket:send("RSET\r\n")
  socket:receive_lines(1)
  socket:close()

  local output = stdnse.output_table()
  if rcpt_ok then
    output["Open Relay"] = "VULNERABLE"
    output["Severity"] = "Critical"
    output["Recommendation"] = "Configure relay restrictions"
  else
    output["Open Relay"] = "Not vulnerable"
  end
  return output
end
