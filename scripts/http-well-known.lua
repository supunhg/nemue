local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks the .well-known directory for common configuration files.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local well_known_files = {
    "/.well-known/security.txt",
    "/.well-known/openid-configuration",
    "/.well-known/change-password",
    "/.well-known/host-meta",
    "/.well-known/assetlinks.json",
    "/.well-known/apple-app-site-association",
  }

  table.insert(result, "Checking .well-known directory:")

  for _, path in ipairs(well_known_files) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "Found: " .. path)
    end
  end

  return stdnse.format_output(true, result)
end
