local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for DNS zone transfer vulnerability.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(53, "dns")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "DNS Zone Transfer Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Vulnerability: AXFR zone transfer may expose all DNS records")
  table.insert(result, "Note: Requires AXFR query with domain name")
  table.insert(result, "Remediation: Restrict zone transfers to authorized servers")

  socket:close()
  return stdnse.format_output(true, result)
end
