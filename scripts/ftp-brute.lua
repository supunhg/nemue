local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force password guessing against FTP service.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local credentials = {
    {user = "admin", pass = "admin"},
    {user = "admin", pass = "password"},
    {user = "root", pass = "root"},
    {user = "root", pass = "toor"},
    {user = "ftp", pass = "ftp"},
    {user = "ftp", pass = "anonymous"},
    {user = "user", pass = "user"},
    {user = "test", pass = "test"},
    {user = "guest", pass = "guest"},
    {user = "backup", pass = "backup"},
  }

  local results = {}
  for _, cred in ipairs(credentials) do
    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)
    if status then
      local response
      socket:receive_lines(1)
      socket:send("USER " .. cred.user .. "\r\n")
      socket:receive_lines(1)
      socket:send("PASS " .. cred.pass .. "\r\n")
      status, response = socket:receive_lines(1)
      if status and response:match("^230") then
        table.insert(results, cred.user .. ":" .. cred.pass)
      end
    end
    socket:close()
  end

  local output = stdnse.output_table()
  output["Tested Credentials"] = #credentials
  output["Successful Logins"] = results
  return output
end
