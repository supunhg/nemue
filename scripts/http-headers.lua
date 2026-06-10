local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for important security headers on HTTP responses.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/")

  if response then
    table.insert(result, "Security Headers Analysis:")

    local headers_to_check = {
      {"x-frame-options", "X-Frame-Options"},
      {"x-content-type-options", "X-Content-Type-Options"},
      {"x-xss-protection", "X-XSS-Protection"},
      {"strict-transport-security", "Strict-Transport-Security"},
      {"content-security-policy", "Content-Security-Policy"},
      {"referrer-policy", "Referrer-Policy"},
      {"permissions-policy", "Permissions-Policy"},
      {"x-permitted-cross-domain-policies", "X-Permitted-Cross-Domain-Policies"},
    }

    for _, h in ipairs(headers_to_check) do
      local value = response.header[h[1]]
      if value then
        table.insert(result, h[2] .. ": " .. value:sub(1, 60))
      else
        table.insert(result, h[2] .. ": MISSING")
      end
    end

    local server = response.header["server"]
    if server then
      table.insert(result, "Server: " .. server)
    end
  end

  return stdnse.format_output(true, result)
end
