local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects HTTP server technology and framework information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/")

  if response then
    table.insert(result, "HTTP Technology Detection:")

    local server = response.header["server"]
    if server then
      table.insert(result, "Server: " .. server)
    end

    local powered = response.header["x-powered-by"]
    if powered then
      table.insert(result, "X-Powered-By: " .. powered)
    end

    local asp = response.header["x-aspnet-version"]
    if asp then
      table.insert(result, "ASP.NET Version: " .. asp)
    end

    local body = response.body or ""
    if body:match("wp%-content") then
      table.insert(result, "CMS: WordPress detected")
    end
    if body:match("Joomla") then
      table.insert(result, "CMS: Joomla detected")
    end
    if body:match("Drupal") then
      table.insert(result, "CMS: Drupal detected")
    end
  end

  return stdnse.format_output(true, result)
end
