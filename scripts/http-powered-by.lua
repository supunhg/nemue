local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects X-Powered-By header information disclosure.
Identifies server-side technologies, frameworks, and their versions.
]]

---
-- @usage
-- nmap --script http-powered-by -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-powered-by:
-- |   X-Powered-By Disclosure:
-- |     X-Powered-By: Express
-- |     Technology: Node.js Express
-- |   [!] Server technology disclosed

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local tech_signatures = {
  ["PHP"] = "PHP (Hypertext Preprocessor)",
  ["Express"] = "Node.js Express",
  ["ASP.NET"] = "Microsoft ASP.NET",
  ["Servlet"] = "Java Servlet",
  ["JSF"] = "JavaServer Faces",
  ["Next.js"] = "Next.js (React)",
  ["Nuxt"] = "Nuxt.js (Vue)",
  ["SvelteKit"] = "SvelteKit",
  ["Remix"] = "Remix Framework",
  ["Laravel"] = "Laravel (PHP)",
  ["Django"] = "Django (Python)",
  ["Rails"] = "Ruby on Rails",
  ["Spring"] = "Spring Framework (Java)",
  ["Vert.x"] = "Eclipse Vert.x",
  ["Cowboy"] = "Cowboy (Erlang)",
  ["Phusion"] = "Phusion Passenger",
  ["PleskLin"] = "Plesk Linux",
  ["Powered"] = "Unknown"
}

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local response = http.get(host, port, path)

  if not response or not response.header then
    return "No response received"
  end

  local output = {}
  local issues = {}

  local powered_by = response.header["x-powered-by"]

  table.insert(output, "X-Powered-By Disclosure:")
  table.insert(output, string.format("  X-Powered-By: %s", powered_by or "not set"))
  table.insert(output, "")

  if powered_by then
    -- Detect technology
    local detected_tech = "Unknown"
    for pattern, tech in pairs(tech_signatures) do
      if string.find(powered_by, pattern) then
        detected_tech = tech
        break
      end
    end

    table.insert(output, string.format("  Technology: %s", detected_tech))

    -- Check for version disclosure
    local version = string.match(powered_by, "[%d]+%.[%d]+[%d%.]*")
    if version then
      table.insert(output, string.format("  Version Detected: %s", version))
      table.insert(issues, string.format("Version number exposed: %s", version))
    end

    table.insert(issues, "X-Powered-By header discloses server technology")
    table.insert(issues, "Remove X-Powered-By header to reduce attack surface")
  else
    table.insert(output, "[+] X-Powered-By header not present (good)")
  end

  -- Check for additional disclosure headers
  local asp_version = response.header["x-aspnetmvc-version"]
  if asp_version then
    table.insert(output, string.format("  X-AspNetMvc-Version: %s", asp_version))
    table.insert(issues, "ASP.NET MVC version disclosed")
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
