local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Enumerates etcd key-value store.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(2379, "etcd")

action = function(host, port)
  local result = {}

  table.insert(result, "etcd Keys Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local paths = {
    "/v2/keys/",
    "/v2/keys/?recursive=true",
    "/version",
    "/health"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[+] etcd endpoint accessible: " .. path)
    end
  end

  table.insert(result, "[!] etcd stores all K8s cluster state and secrets")

  return stdnse.format_output(true, result)
end
