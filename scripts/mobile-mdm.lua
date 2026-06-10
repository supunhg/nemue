local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Detects Mobile Device Management (MDM) solutions.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(443, "https")

action = function(host, port)
  local result = {}

  table.insert(result, "MDM Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local mdm_paths = {
    "/mdm/enroll",
    "/api/mdm",
    "/devicemanagement/api",
    "/scep",
    "/enrollment",
    "/apple-mdm",
    "/profile"
  }

  for _, path in ipairs(mdm_paths) do
    local response = http.get(host, port, path)
    if response and response.status ~= 404 then
      table.insert(result, "[+] MDM endpoint found: " .. path .. " (HTTP " .. response.status .. ")")
    end
  end

  table.insert(result, "[!] MDM solutions manage mobile device policies")

  return stdnse.format_output(true, result)
end
