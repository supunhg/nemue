local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if the SMTP server allows VRFY user enumeration.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local test_users = {"root", "admin", "postmaster", "webmaster", "info", "test", "user"}

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

  local results = {}
  for _, user in ipairs(test_users) do
    socket:send("VRFY " .. user .. "\r\n")
    status, line = socket:receive_lines(1)
    if status then
      local resp = line:gsub("\r?\n$", "")
      if resp:match("^250") or resp:match("^252") then
        table.insert(results, user .. " - EXISTS")
      elseif resp:match("^550") then
        table.insert(results, user .. " - Not found")
      else
        table.insert(results, user .. " - " .. resp)
      end
    end
  end

  socket:close()

  local output = stdnse.output_table()
  output["VRFY Results"] = results
  output["Note"] = "VRFY can be used to enumerate valid usernames"
  return output
end
