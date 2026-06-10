local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Sends a DNS ANY query to enumerate all record types for a domain.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local domain = stdnse.get_script_args("dns-any.domain") or host.name

  local status, response = dns.query(domain, {host = host.ip, port = port.number, dtype = "ANY"})

  local output = stdnse.output_table()
  output["Domain"] = domain
  if status and response then
    output["ANY Response"] = response
    output["Note"] = "ANY query returns all cached record types"
  else
    output["ANY Response"] = "No response or query refused"
    output["Note"] = "Many servers now refuse ANY queries (RFC 8482)"
  end
  return output
end
