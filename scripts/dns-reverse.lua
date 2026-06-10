local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Performs reverse DNS lookups for discovered IP addresses.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local ip = host.ip
  local status, response = dns.query(ip, {host = host.ip, port = port.number, dtype = "PTR"})

  local output = stdnse.output_table()
  output["IP Address"] = ip
  if status and response then
    output["Hostname"] = response
  else
    output["Hostname"] = "No PTR record"
  end
  return output
end
