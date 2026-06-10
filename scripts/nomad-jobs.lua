local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Enumerates HashiCorp Nomad jobs and allocations.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(4646, "http")

action = function(host, port)
  local result = {}

  table.insert(result, "Nomad Jobs Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local paths = {
    "/v1/jobs",
    "/v1/allocations",
    "/v1/nodes",
    "/v1/status/leader"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[+] Nomad endpoint accessible: " .. path)
    end
  end

  table.insert(result, "[!] Exposed Nomad API allows job submission")

  return stdnse.format_output(true, result)
end
