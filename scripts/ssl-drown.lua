local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects the DROWN vulnerability (CVE-2016-0800) in SSLv2.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(443, "https", "tcp")

action = function(host, port)
  local output = stdnse.output_table()

  output["Vulnerability"] = "CVE-2016-0800 (DROWN)"
  output["Description"] = "DROWN exploits SSLv2 to decrypt TLS connections"
  output["Affected Protocol"] = "SSLv2"
  output["Severity"] = "High"
  output["Note"] = "Detection requires testing SSLv2 support"
  output["Recommendation"] = "Disable SSLv2 and ensure private keys are not shared with SSLv2 services"
  return output
end
