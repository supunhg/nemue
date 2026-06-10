local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Discovers supported HTTP methods using OPTIONS request.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.generic_request(host, port, "OPTIONS / HTTP/1.0")

  if response then
    table.insert(result, "HTTP Methods:")
    local allow = response.header["allow"]
    if allow then
      for method in allow:gmatch("(%u+)") do
        table.insert(result, "  " .. method)
      end
    else
      table.insert(result, "Allow header not present")
      local test_methods = {"GET", "POST", "PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}
      for _, m in ipairs(test_methods) do
        local r = http.generic_request(host, port, m .. " / HTTP/1.0")
        if r and r.status ~= 405 and r.status ~= 501 then
          table.insert(result, "  " .. m .. " (status: " .. r.status .. ")")
        end
      end
    end
  end

  return stdnse.format_output(true, result)
end
