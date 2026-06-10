local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Detects exposed HashiCorp Vault secrets.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(8200, "https")

action = function(host, port)
  local result = {}

  table.insert(result, "Vault Secrets Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local paths = {
    "/v1/sys/health",
    "/v1/sys/mounts",
    "/v1/secret/data",
    "/v1/auth/token/lookup-self"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[+] Vault endpoint accessible: " .. path)
    end
  end

  table.insert(result, "[!] Vault should require authentication for all paths")

  return stdnse.format_output(true, result)
end
