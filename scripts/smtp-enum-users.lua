local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates SMTP users using VRFY and RCPT TO methods.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local common_users = {
    "root", "admin", "postmaster", "webmaster", "info", "support",
    "sales", "contact", "noreply", "mailer-daemon", "nobody",
    "www", "ftp", "mail", "operator", "games", "gopher"
  }

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

  local vrfy_results = {}
  for _, user in ipairs(common_users) do
    socket:send("VRFY " .. user .. "\r\n")
    status, line = socket:receive_lines(1)
    if status then
      local resp = line:gsub("\r?\n$", "")
      if resp:match("^250") or resp:match("^252") then
        table.insert(vrfy_results, user)
      end
    end
  end

  socket:close()

  local output = stdnse.output_table()
  output["Users Found"] = vrfy_results
  output["Method"] = "VRFY"
  output["Total Tested"] = #common_users
  return output
end
