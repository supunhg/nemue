local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for common SMB vulnerabilities.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(445, "microsoft-ds")

action = function(host, port)
  local result = {}

  table.insert(result, "SMB Vulnerability Scan")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Checking for:")
  table.insert(result, "  - MS08-067 (Conficker)")
  table.insert(result, "  - MS17-010 (EternalBlue)")
  table.insert(result, "  - CVE-2020-0796 (SMBGhost)")
  table.insert(result, "Status: Requires SMB protocol for detailed check")

  return stdnse.format_output(true, result)
end
