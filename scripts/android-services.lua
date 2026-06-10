local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Enumerates Android services and management interfaces.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5555, "adb")

action = function(host, port)
  local result = {}

  table.insert(result, "Android Services Enumeration")
  table.insert(result, "Target: " .. host.ip)

  local ports = {5555, 8080, 8443, 9090}

  for _, p in ipairs(ports) do
    local sock = nmap.new_socket()
    local status = sock:connect(host.ip, p)
    if status then
      table.insert(result, "[+] Service on port " .. p .. " is open")
    end
    sock:close()
  end

  table.insert(result, "[!] Android devices may expose management interfaces")

  return stdnse.format_output(true, result)
end
