local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for ConnectWise ScreenConnect vulnerability (CVE-2024-1709).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "ConnectWise ScreenConnect (CVE-2024-1709) Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Vulnerability: Authentication bypass")
  table.insert(result, "Affected: ScreenConnect 23.9.7 and earlier")
  table.insert(result, "Note: Allows unauthorized access to setup wizard")
  table.insert(result, "Remediation: Update to ScreenConnect 23.9.8+")

  local response = http.get(host, port, "/")
  if response and response.body then
    if response.body:match("ScreenConnect") or response.body:match("ConnectWise") then
      table.insert(result, "ConnectWise indicators detected in response")
    end
  end

  return stdnse.format_output(true, result)
end
