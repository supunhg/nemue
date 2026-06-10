local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Enumerates Kubernetes configmaps.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(6443, "https")

action = function(host, port)
  local result = {}

  table.insert(result, "Kubernetes ConfigMaps Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local paths = {
    "/api/v1/configmaps",
    "/api/v1/namespaces/default/configmaps",
    "/api/v1/namespaces/kube-system/configmaps"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[!] K8s configmaps accessible: " .. path)
    end
  end

  table.insert(result, "[!] ConfigMaps may contain sensitive configuration data")

  return stdnse.format_output(true, result)
end
