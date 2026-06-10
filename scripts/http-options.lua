local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Sends an OPTIONS request and analyzes the response.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.generic_request(host, port, "OPTIONS * HTTP/1.0")

  if response then
    table.insert(result, "OPTIONS response:")
    table.insert(result, "Status: " .. response.status)

    local allow = response.header["allow"]
    if allow then
      table.insert(result, "Allowed methods: " .. allow)
    end

    local public = response.header["public"]
    if public then
      table.insert(result, "Public methods: " .. public)
    end
  end

  return stdnse.format_output(true, result)
end
