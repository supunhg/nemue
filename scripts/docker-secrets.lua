local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Detects exposed Docker secrets and sensitive configurations.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(2375, "docker")

action = function(host, port)
  local result = {}

  table.insert(result, "Docker Secrets Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local paths = {
    "/secrets",
    "/configs",
    "/volumes"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[!] Docker " .. path .. " endpoint accessible")
    end
  end

  local response = http.get(host, port, "/secrets")
  if response and response.status == 200 then
    table.insert(result, "[!] CRITICAL: Docker secrets exposed without auth")
  end

  table.insert(result, "[!] Docker API should never be exposed without TLS")

  return stdnse.format_output(true, result)
end
