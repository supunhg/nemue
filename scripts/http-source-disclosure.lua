local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for source code disclosure vulnerabilities.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local source_paths = {
    "/.git/HEAD", "/.svn/entries", "/.hg/dirstate",
    "/.env", "/.DS_Store", "/.htaccess",
    "/web.config", "/appsettings.json",
  }

  table.insert(result, "Source Code Disclosure Check:")

  for _, path in ipairs(source_paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "Exposed: " .. path)
      if path:match("%.git") then
        table.insert(result, "WARNING: Git repository exposed")
      end
      if path:match("%.env") then
        table.insert(result, "WARNING: Environment file exposed")
      end
    end
  end

  if #result == 1 then
    table.insert(result, "No source code disclosure detected")
  end

  return stdnse.format_output(true, result)
end
