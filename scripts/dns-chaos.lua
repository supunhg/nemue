local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Queries the DNS CHAOS class for server information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local queries = {
    {name = "version.bind", dtype = "TXT"},
    {name = "version.server", dtype = "TXT"},
    {name = "hostname.bind", dtype = "TXT"},
    {name = "id.server", dtype = "TXT"},
  }

  local results = {}
  for _, q in ipairs(queries) do
    local status, response = dns.query(q.name, {host = host.ip, port = port.number, dtype = q.dtype, class = "CHAOS"})
    if status and response then
      table.insert(results, q.name .. ": " .. tostring(response))
    end
  end

  local output = stdnse.output_table()
  output["CHAOS Class Results"] = results
  if #results == 0 then
    output["Note"] = "Server does not respond to CHAOS class queries"
  end
  return output
end
