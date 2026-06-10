local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests if the SMTP server allows EXPN mailing list enumeration.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local test_lists = {"postmaster", "root", "admin", "all", "staff", "users", "mail"}

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
  for _, list in ipairs(test_lists) do
    socket:send("EXPN " .. list .. "\r\n")
    status, line = socket:receive_lines(1)
    if status then
      local resp = line:gsub("\r?\n$", "")
      if resp:match("^250") then
        table.insert(results, list .. " - Expanded")
      elseif resp:match("^550") then
        table.insert(results, list .. " - Not found")
      else
        table.insert(results, list .. " - " .. resp)
      end
    end
  end

  socket:close()

  local output = stdnse.output_table()
  output["EXPN Results"] = results
  output["Note"] = "EXPN reveals mailing list members"
  return output
end
