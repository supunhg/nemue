local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Enumerates Kubernetes services.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(6443, "https")

action = function(host, port)
  local result = {}

  table.insert(result, "Kubernetes Services Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local paths = {
    "/api/v1/services",
    "/api/v1/namespaces/default/services",
    "/apis/apps/v1/deployments"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[+] K8s services accessible: " .. path)
    end
  end

  table.insert(result, "[!] Unauthenticated K8s API allows cluster takeover")

  return stdnse.format_output(true, result)
end
