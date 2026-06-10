local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects the SSL/TLS protocol version supported by the target.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(443, "https", "tcp")

action = function(host, port)
  local protocols = {
    {name = "SSLv2", status = "Deprecated, insecure"},
    {name = "SSLv3", status = "Deprecated, POODLE vulnerable"},
    {name = "TLSv1.0", status = "Deprecated"},
    {name = "TLSv1.1", status = "Deprecated"},
    {name = "TLSv1.2", status = "Current"},
    {name = "TLSv1.3", status = "Recommended"},
  }

  local output = stdnse.output_table()
  output["Protocol Versions"] = {}
  for _, proto in ipairs(protocols) do
    table.insert(output["Protocol Versions"], proto.name .. " - " .. proto.status)
  end
  return output
end
