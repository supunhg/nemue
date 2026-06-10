local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for HTTP host header injection vulnerabilities.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local malicious_hosts = {
    "evil.com",
    "localhost",
    "127.0.0.1",
  }

  table.insert(result, "Host Header Injection Check:")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  for _, mh in ipairs(malicious_hosts) do
    local response = http.get(host, port, "/", {header = {["Host"] = mh}})
    if response and response.body then
      if response.body:match(mh) then
        table.insert(result, "WARNING: Host header reflected: " .. mh)
      end
    end
  end

  local response = http.get(host, port, "/")
  if response then
    local loc = response.header["location"]
    if loc and loc:match("evil%.com") then
      table.insert(result, "CRITICAL: Open redirect detected")
    end
  end

  return stdnse.format_output(true, result)
end
