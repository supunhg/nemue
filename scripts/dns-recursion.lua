local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Tests if the DNS server allows recursive queries from external sources.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local status, response = dns.query("www.google.com", {host = host.ip, port = port.number, dtype = "A", recurse = true})

  local output = stdnse.output_table()
  if status and response then
    output["Recursion"] = "Allowed"
    output["Status"] = "VULNERABLE (open resolver)"
    output["Severity"] = "Medium"
    output["Recommendation"] = "Restrict recursion to trusted clients only"
  else
    output["Recursion"] = "Denied"
    output["Status"] = "Secure"
  end
  return output
end
