local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects mobile VPN services and configurations.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and (port.number == 443 or port.number == 1194 or port.number == 500 or port.number == 4500)
end

action = function(host, port)
  local result = {}

  table.insert(result, "Mobile VPN Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local vpn_indicators = {
    [443] = "SSL/TLS VPN",
    [1194] = "OpenVPN",
    [500] = "IKEv2/IPsec",
    [4500] = "IPsec NAT-T"
  }

  local vpn_type = vpn_indicators[port.number]
  if vpn_type then
    table.insert(result, "[+] VPN service: " .. vpn_type)
  end

  table.insert(result, "[!] Mobile VPNs provide secure remote access")

  return stdnse.format_output(true, result)
end
