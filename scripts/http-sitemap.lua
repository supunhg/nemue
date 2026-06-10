local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for sitemap.xml and extracts listed URLs.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/sitemap.xml")

  if response and response.status == 200 then
    table.insert(result, "sitemap.xml found")
    local body = response.body or ""
    local count = 0
    for url in body:gmatch("<loc>(.-)</loc>") do
      count = count + 1
      if count <= 10 then
        table.insert(result, "URL: " .. url)
      end
    end
    if count > 10 then
      table.insert(result, "... and " .. (count - 10) .. " more URLs")
    end
    table.insert(result, "Total URLs: " .. count)
  else
    table.insert(result, "sitemap.xml not found")
  end

  return stdnse.format_output(true, result)
end
