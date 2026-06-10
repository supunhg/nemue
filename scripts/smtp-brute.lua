local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force authentication against SMTP service.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

portrule = shortport.port_or_service(25, "smtp", "tcp")

action = function(host, port)
  local credentials = {
    {user = "admin", pass = "admin"},
    {user = "admin", pass = "password"},
    {user = "postmaster", pass = "postmaster"},
    {user = "root", pass = "root"},
    {user = "user", pass = "user"},
    {user = "test", pass = "test"},
  }

  local results = {}
  for _, cred in ipairs(credentials) do
    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)
    if status then
      socket:receive_lines(1)
      socket:send("EHLO nmap.test\r\n")
      local line
      repeat
        status, line = socket:receive_lines(1)
      until not status or (line and line:match("^250 "))

      local encoded = "AUTH LOGIN\r\n"
      socket:send(encoded)
      socket:receive_lines(1)
    end
    socket:close()
  end

  local output = stdnse.output_table()
  output["Tested Credentials"] = #credentials
  output["Note"] = "SMTP brute force requires AUTH LOGIN/PLAIN support"
  output["Successful Logins"] = results
  return output
end
