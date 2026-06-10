local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates valid recipients using RCPT TO command.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local test_users = {"root", "admin", "postmaster", "webmaster", "info", "test", "user", "nobody"}

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

  socket:send("MAIL FROM:<test@nmap.test>\r\n")
  socket:receive_lines(1)

  local results = {}
  for _, user in ipairs(test_users) do
    socket:send("RCPT TO:<" .. user .. ">\r\n")
    status, line = socket:receive_lines(1)
    if status then
      local resp = line:gsub("\r?\n$", "")
      if resp:match("^250") or resp:match("^251") then
        table.insert(results, user .. " - Valid")
      else
        table.insert(results, user .. " - Invalid")
      end
    end
  end

  socket:send("RSET\r\n")
  socket:receive_lines(1)
  socket:close()

  local output = stdnse.output_table()
  output["RCPT TO Results"] = results
  return output
end
