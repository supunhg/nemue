local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Detects exposed mobile configuration profiles.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(443, "https")

action = function(host, port)
  local result = {}

  table.insert(result, "Mobile Configuration Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local config_paths = {
    "/enroll",
    "/profile",
    "/configuration",
    "/.mobileconfig",
    "/mdm/enroll",
    "/scep"
  }

  for _, path in ipairs(config_paths) do
    local response = http.get(host, port, path)
    if response and response.status ~= 404 then
      table.insert(result, "[+] Config endpoint found: " .. path .. " (HTTP " .. response.status .. ")")
    end
  end

  table.insert(result, "[!] Mobileconfig files can contain Wi-Fi and VPN credentials")

  return stdnse.format_output(true, result)
end
