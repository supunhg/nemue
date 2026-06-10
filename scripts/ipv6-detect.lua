local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects IPv6 services and configurations on targets.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "IPv6 Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  if host.ip:find(":") then
    table.insert(result, "[+] IPv6 address detected")
    table.insert(result, "[+] Address: " .. host.ip)
  else
    table.insert(result, "[*] IPv4 target")
    table.insert(result, "[!] Check for dual-stack IPv6 exposure")
  end

  local ipv6_services = {80, 443, 22, 25, 53}
  for _, p in ipairs(ipv6_services) do
    if port.number == p then
      table.insert(result, "[+] Common IPv6 service on port " .. p)
    end
  end

  table.insert(result, "[!] IPv6 may bypass IPv4 firewall rules")

  return stdnse.format_output(true, result)
end
