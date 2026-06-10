local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Detects exposed Kubernetes secrets.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(6443, "https")

action = function(host, port)
  local result = {}

  table.insert(result, "Kubernetes Secrets Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local paths = {
    "/api/v1/secrets",
    "/api/v1/namespaces/default/secrets",
    "/api/v1/namespaces/kube-system/secrets"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[!] K8s secrets accessible: " .. path)
    end
  end

  table.insert(result, "[!] Kubernetes secrets should require RBAC authentication")

  return stdnse.format_output(true, result)
end
