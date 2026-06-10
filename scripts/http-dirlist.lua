local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for directory listing on common web directories.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local paths = {"/", "/images/", "/css/", "/js/", "/uploads/", "/backup/", "/admin/", "/temp/"}

  table.insert(result, "Directory Listing Check:")

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 and response.body then
      if response.body:match("Index of") or response.body:match("Directory listing") then
        table.insert(result, "Directory listing enabled: " .. path)
      end
    end
  end

  if #result == 1 then
    table.insert(result, "No directory listing found")
  end

  return stdnse.format_output(true, result)
end
