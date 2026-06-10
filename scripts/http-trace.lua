local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks if the TRACE method is enabled on the HTTP server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.generic_request(host, port, "TRACE / HTTP/1.0")

  if response then
    if response.status == 200 then
      table.insert(result, "TRACE method: ENABLED (WARNING)")
      table.insert(result, "Cross-Site Tracing (XST) may be possible")
    elseif response.status == 405 then
      table.insert(result, "TRACE method: Disabled")
    elseif response.status == 501 then
      table.insert(result, "TRACE method: Not implemented")
    else
      table.insert(result, "TRACE method: Status " .. response.status)
    end
  end

  return stdnse.format_output(true, result)
end
