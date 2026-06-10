local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects ASP.NET version disclosure through X-AspNet-Version and related headers.
Identifies the exact .NET framework version running on the server.
]]

---
-- @usage
-- nmap --script http-x-aspnet-version -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-x-aspnet-version:
-- |   ASP.NET Version Disclosure:
-- |     X-AspNet-Version: 4.0.30319
-- |     Framework: .NET Framework 4.x
-- |   [!] ASP.NET version disclosed

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local dotnet_versions = {
  ["4%.0%.30319"] = ".NET Framework 4.0/4.5/4.6/4.7/4.8",
  ["2%.0%.50727"] = ".NET Framework 2.0/3.0/3.5",
  ["1%.1%.4322"] = ".NET Framework 1.1",
  ["1%.0%.3705"] = ".NET Framework 1.0"
}

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local response = http.get(host, port, path)

  if not response or not response.header then
    return "No response received"
  end

  local output = {}
  local issues = {}

  local aspnet_version = response.header["x-aspnet-version"]
  local aspnetmvc_version = response.header["x-aspnetmvc-version"]
  local aspnet_webpages = response.header["x-aspnet-webpages-version"]
  local powered_by = response.header["x-powered-by"]

  table.insert(output, "ASP.NET Version Disclosure:")
  table.insert(output, "")

  if aspnet_version then
    table.insert(output, string.format("  X-AspNet-Version: %s", aspnet_version))

    for pattern, framework in pairs(dotnet_versions) do
      if string.match(aspnet_version, pattern) then
        table.insert(output, string.format("  Framework: %s", framework))
        break
      end
    end

    table.insert(issues, "ASP.NET version disclosed via X-AspNet-Version header")
  end

  if aspnetmvc_version then
    table.insert(output, string.format("  X-AspNetMvc-Version: %s", aspnetmvc_version))
    table.insert(issues, "ASP.NET MVC version disclosed")
  end

  if aspnet_webpages then
    table.insert(output, string.format("  X-AspNetWebPages-Version: %s", aspnet_webpages))
    table.insert(issues, "ASP.NET WebPages version disclosed")
  end

  if powered_by and string.find(powered_by, "ASP%.NET") then
    table.insert(output, string.format("  X-Powered-By: %s", powered_by))
    table.insert(issues, "ASP.NET disclosed via X-Powered-By header")
  end

  -- Check for ASP.NET cookies
  local cookies = response.header["set-cookie"]
  if cookies then
    if string.find(cookies, "ASP%.NET_SessionId") then
      table.insert(output, "  Cookie: ASP.NET_SessionId detected")
      table.insert(issues, "ASP.NET session cookie present")
    end
    if string.find(cookies, "__RequestVerificationToken") then
      table.insert(output, "  Anti-Forgery Token: present")
    end
  end

  if not aspnet_version and not aspnetmvc_version and not aspnet_webpages then
    if powered_by and string.find(powered_by, "ASP%.NET") then
      table.insert(output, "  ASP.NET detected via X-Powered-By only")
    else
      table.insert(output, "[+] No ASP.NET version headers detected")
    end
  end

  if #issues > 0 then
    table.insert(output, "")
    table.insert(output, "Issues Found:")
    for _, issue in ipairs(issues) do
      table.insert(output, string.format("  [!] %s", issue))
    end
    table.insert(output, "")
    table.insert(output, "Recommendation: Remove version headers in web.config")
  end

  return table.concat(output, "\n")
end
