local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Analyzes Content Security Policy (CSP) headers.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/")

  if response then
    local csp = response.header["content-security-policy"]
    local csp_report = response.header["content-security-policy-report-only"]

    table.insert(result, "CSP Analysis:")

    if csp then
      table.insert(result, "CSP Header: Present")
      if csp:match("unsafe%-inline") then
        table.insert(result, "WARNING: unsafe-inline detected")
      end
      if csp:match("unsafe%-eval") then
        table.insert(result, "WARNING: unsafe-eval detected")
      end
      if csp:match("%*") then
        table.insert(result, "WARNING: Wildcard source detected")
      end
    else
      table.insert(result, "CSP Header: NOT SET")
    end

    if csp_report then
      table.insert(result, "CSP Report-Only: Present")
    end
  end

  return stdnse.format_output(true, result)
end
