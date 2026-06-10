local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Clickjacking protection via X-Frame-Options and CSP frame-ancestors.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/")

  if response then
    local xfo = response.header["x-frame-options"]
    local csp = response.header["content-security-policy"]

    table.insert(result, "Clickjacking Protection:")

    if xfo then
      table.insert(result, "X-Frame-Options: " .. xfo)
    else
      table.insert(result, "X-Frame-Options: NOT SET (vulnerable)")
    end

    if csp and csp:match("frame%-ancestors") then
      local fa = csp:match("frame%-ancestors%s+(%S+)")
      table.insert(result, "CSP frame-ancestors: " .. (fa or "present"))
    else
      table.insert(result, "CSP frame-ancestors: NOT SET")
    end

    if not xfo and not (csp and csp:match("frame%-ancestors")) then
      table.insert(result, "WARNING: Site may be vulnerable to Clickjacking")
    end
  end

  return stdnse.format_output(true, result)
end
