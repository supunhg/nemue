local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Enumerates Consul service catalog.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(8500, "http")

action = function(host, port)
  local result = {}

  table.insert(result, "Consul Services Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local paths = {
    "/v1/catalog/services",
    "/v1/catalog/nodes",
    "/v1/agent/services",
    "/v1/kv/?recurse"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[+] Consul endpoint accessible: " .. path)
    end
  end

  table.insert(result, "[!] Exposed Consul API allows service discovery")

  return stdnse.format_output(true, result)
end
