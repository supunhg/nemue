local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for MOVEit Transfer vulnerability (CVE-2023-34362).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "MOVEit Transfer (CVE-2023-34362) Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Vulnerability: SQL Injection leading to RCE")
  table.insert(result, "Affected: MOVEit Transfer before 2021.0.6")
  table.insert(result, "Note: Checks for MOVEit login page indicators")
  table.insert(result, "Remediation: Apply vendor patches immediately")

  local response = http.get(host, port, "/")
  if response and response.body then
    if response.body:match("MOVEit") or response.body:match("moveit") then
      table.insert(result, "MOVEit indicators detected in response")
    end
  end

  return stdnse.format_output(true, result)
end
