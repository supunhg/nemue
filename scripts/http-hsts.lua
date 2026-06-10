local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for HTTP Strict Transport Security (HSTS) header.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/")

  if response then
    local hsts = response.header["strict-transport-security"]

    table.insert(result, "HSTS Configuration:")
    if hsts then
      table.insert(result, "Strict-Transport-Security: " .. hsts)
      local max_age = hsts:match("max%-age=(%d+)")
      if max_age then
        table.insert(result, "Max-Age: " .. max_age .. " seconds")
      end
      if hsts:match("includeSubDomains") then
        table.insert(result, "IncludeSubDomains: Yes")
      end
    else
      table.insert(result, "HSTS: NOT SET")
      table.insert(result, "WARNING: Site does not enforce HTTPS via HSTS")
    end
  end

  return stdnse.format_output(true, result)
end
