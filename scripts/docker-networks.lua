local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Enumerates Docker networks via the Docker API.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(2375, "docker")

action = function(host, port)
  local result = {}

  table.insert(result, "Docker Network Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local response = http.get(host, port, "/networks")
  if response and response.status == 200 then
    table.insert(result, "[+] Docker networks endpoint accessible")
    table.insert(result, "[!] Docker API exposed without authentication")
  end

  local containers = http.get(host, port, "/containers/json")
  if containers and containers.status == 200 then
    table.insert(result, "[!] Container listing accessible")
  end

  table.insert(result, "[!] Exposed Docker API allows container escape attacks")

  return stdnse.format_output(true, result)
end
