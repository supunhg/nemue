local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for HTTP parameter pollution vulnerabilities.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}

  table.insert(result, "HTTP Parameter Pollution Check:")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local base = http.get(host, port, "/?test=normal")
  local poll1 = http.get(host, port, "/?test=normal&test=inject")
  local poll2 = http.get(host, port, "/?test=normal%26test=inject")

  if base and poll1 then
    if base.status ~= poll1.status then
      table.insert(result, "HPP indicator: Different status codes with duplicate params")
    end
  end

  table.insert(result, "Note: Full HPP testing requires application-specific parameters")

  return stdnse.format_output(true, result)
end
