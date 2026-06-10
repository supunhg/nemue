local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Attempts to determine the version of the DNS server using CHAOS class TXT queries.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local versions = {
    "version.bind", "version.server"
  }

  local results = {}
  for _, name in ipairs(versions) do
    local status, response = dns.query(name, {host = host.ip, port = port.number, dtype = "TXT", class = "CHAOS"})
    if status then
      table.insert(results, name .. ": " .. (response or "Unknown"))
    end
  end

  local output = stdnse.output_table()
  if #results > 0 then
    output["Version Info"] = results
  else
    output["Version Info"] = "Not disclosed"
  end
  return output
end
