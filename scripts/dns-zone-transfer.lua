local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Attempts a DNS zone transfer (AXFR) to enumerate all records in a zone.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local domain = stdnse.get_script_args("dns-zone-transfer.domain") or host.name

  local status, response = dns.query(domain, {host = host.ip, port = port.number, dtype = "AXFR"})

  local output = stdnse.output_table()
  output["Domain"] = domain
  if status and response then
    output["Zone Transfer"] = "Allowed"
    output["Status"] = "VULNERABLE"
    output["Severity"] = "High"
    output["Records"] = response
    output["Recommendation"] = "Restrict zone transfers to authorized secondary servers"
  else
    output["Zone Transfer"] = "Denied"
    output["Status"] = "Secure"
  end
  return output
end
