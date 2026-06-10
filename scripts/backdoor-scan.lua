local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Scans for common backdoor ports and suspicious services.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Backdoor Scan")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local backdoor_ports = {
    [4444] = "Metasploit default handler",
    [5555] = "Android Debug Bridge",
    [6666] = "IRC backdoor",
    [6667] = "IRC backdoor",
    [12345] = "NetBus trojan",
    [31337] = "Back Orifice",
    [27374] = "Sub7 trojan",
    [1243] = "Sub7 trojan",
    [6711] = "Sub7 trojan",
    [6776] = "Back Orifice 2000",
    [8080] = "HTTP proxy/backdoor"
  }

  local risk = backdoor_ports[port.number]
  if risk then
    table.insert(result, "[!] SUSPICIOUS: " .. risk)
    table.insert(result, "[!] Investigate this service immediately")
  end

  if port.service and port.service.name then
    local suspicious = {"backdoor", "trojan", "shell", "rootkit"}
    for _, pattern in ipairs(suspicious) do
      if port.service.name:lower():find(pattern) then
        table.insert(result, "[!] CRITICAL: Suspicious service name: " .. port.service.name)
      end
    end
  end

  table.insert(result, "[!] Regular scanning helps detect unauthorized services")

  return stdnse.format_output(true, result)
end
