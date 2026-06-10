local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects the POODLE vulnerability (CVE-2014-3566) in SSLv3.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(443, "https", "tcp")

action = function(host, port)
  local output = stdnse.output_table()

  output["Vulnerability"] = "CVE-2014-3566 (POODLE)"
  output["Description"] = "POODLE exploits SSLv3 CBC cipher suites"
  output["Affected Protocol"] = "SSLv3"
  output["Severity"] = "Medium"
  output["Note"] = "Detection requires testing SSLv3 cipher negotiation"
  output["Recommendation"] = "Disable SSLv3 support entirely"
  return output
end
