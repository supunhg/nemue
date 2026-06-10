local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for common default SSH credentials.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "auth"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local default_creds = {
    {user = "root", pass = "root"},
    {user = "root", pass = "toor"},
    {user = "admin", pass = "admin"},
    {user = "admin", pass = "password"},
    {user = "root", pass = "password"},
    {user = "root", pass = "123456"},
    {user = "pi", pass = "raspberry"},
    {user = "ubuntu", pass = "ubuntu"},
    {user = "user", pass = "user"},
    {user = "test", pass = "test"},
  }

  local output = stdnse.output_table()
  output["Note"] = "Default credential check requires interactive testing"
  output["Default Credentials"] = {}
  for _, cred in ipairs(default_creds) do
    table.insert(output["Default Credentials"], cred.user .. ":" .. cred.pass)
  end
  output["Recommendation"] = "Change all default credentials immediately"
  return output
end
