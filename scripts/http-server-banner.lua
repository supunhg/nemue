local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Analyzes the Server header for information disclosure.
Identifies web server software, version numbers, and operating system details.
]]

---
-- @usage
-- nmap --script http-server-banner -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-server-banner:
-- |   Server Banner Analysis:
-- |     Server: Apache/2.4.54 (Ubuntu)
-- |     Software: Apache 2.4.54
-- |     OS: Ubuntu
-- |   [!] Server version and OS disclosed

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local server_patterns = {
  { pattern = "Apache/([%d%.]+)%s*%(?(.-)%)?", software = "Apache", os_field = 2 },
  { pattern = "nginx/([%d%.]+)", software = "Nginx", os_field = nil },
  { pattern = "Microsoft%-IIS/([%d%.]+)", software = "Microsoft IIS", os_field = nil },
  { pattern = "LiteSpeed/([%d%.]+)", software = "LiteSpeed", os_field = nil },
  { pattern = "Caddy", software = "Caddy", os_field = nil },
  { pattern = "lighttpd/([%d%.]+)", software = "Lighttpd", os_field = nil },
  { pattern = "Cherokee", software = "Cherokee", os_field = nil },
  { pattern = "TornadoServer/([%d%.]+)", software = "Tornado", os_field = nil },
  { pattern = "Gunicorn/([%d%.]+)", software = "Gunicorn", os_field = nil },
  { pattern = "uvicorn", software = "Uvicorn", os_field = nil },
  { pattern = "Jetty%(?(.-)%)?", software = "Jetty", os_field = 1 },
  { pattern = "WebServer", software = "Unknown Web Server", os_field = nil }
}

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local response = http.get(host, port, path)

  if not response or not response.header then
    return "No response received"
  end

  local output = {}
  local issues = {}

  local server = response.header["server"]

  table.insert(output, "Server Banner Analysis:")
  table.insert(output, string.format("  Server: %s", server or "not set"))
  table.insert(output, "")

  if server then
    local detected = false
    for _, sig in ipairs(server_patterns) do
      local version = string.match(server, sig.pattern)
      if version or string.find(server, sig.software) then
        table.insert(output, string.format("  Software: %s %s", sig.software, version or ""))

        if version then
          table.insert(issues, string.format("Server version disclosed: %s %s", sig.software, version))
        end

        if sig.os_field then
          local os_info = string.match(server, sig.pattern)
          if os_info and os_info ~= "" then
            table.insert(output, string.format("  OS Hint: %s", os_info))
            table.insert(issues, "Operating system information disclosed in Server header")
          end
        end

        detected = true
        break
      end
    end

    if not detected then
      table.insert(output, string.format("  Software: Unknown (%s)", server))
    end

    -- Check for additional modules
    if string.find(server, "mod_") then
      local modules = {}
      for mod in string.gmatch(server, "mod_%a+") do
        table.insert(modules, mod)
      end
      if #modules > 0 then
        table.insert(output, string.format("  Modules: %s", table.concat(modules, ", ")))
        table.insert(issues, "Apache modules disclosed in Server header")
      end
    end

    table.insert(issues, "Server header reveals technology stack")
  else
    table.insert(output, "[+] Server header not present (good)")
  end

  if #issues > 0 then
    table.insert(output, "")
    table.insert(output, "Issues Found:")
    for _, issue in ipairs(issues) do
      table.insert(output, string.format("  [!] %s", issue))
    end
  end

  return table.concat(output, "\n")
end
