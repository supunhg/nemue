local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for common backup files on the web server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local backup_patterns = {
    "/backup.zip", "/backup.tar.gz", "/backup.sql",
    "/db.sql", "/database.sql", "/site.zip",
    "/config.bak", "/index.php.bak", "/.env.bak",
    "/web.config.bak", "/wp-config.php.bak",
  }

  table.insert(result, "Backup File Detection:")

  for _, path in ipairs(backup_patterns) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "Found: " .. path)
    end
  end

  if #result == 1 then
    table.insert(result, "No common backup files found")
  end

  return stdnse.format_output(true, result)
end
