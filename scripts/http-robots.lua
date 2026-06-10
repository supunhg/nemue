local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for robots.txt file and extracts disallowed paths.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/robots.txt")

  if response and response.status == 200 then
    table.insert(result, "robots.txt found")
    local body = response.body or ""
    for line in body:gmatch("[^\r\n]+") do
      if line:match("^[Dd]isallow:") then
        local path = line:match("^[Dd]isallow:%s*(%S+)")
        if path then
          table.insert(result, "Disallowed: " .. path)
        end
      end
    end
  else
    table.insert(result, "robots.txt not found")
  end

  return stdnse.format_output(true, result)
end
