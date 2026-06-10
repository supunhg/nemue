local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Queries the DNS server for NSID (Name Server Identifier).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local status, response = dns.query("", {host = host.ip, port = port.number, dtype = "NS"})

  local output = stdnse.output_table()
  output["NSID"] = "NSID query requires EDNS0 support"
  if status and response then
    output["NS Records"] = response
  end
  output["Note"] = "NSID identifies the specific server in a anycast setup"
  return output
end
