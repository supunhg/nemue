local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs mobile security assessment checks.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Mobile Security Assessment")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local insecure_ports = {
    [21] = "FTP - unencrypted file transfer",
    [23] = "Telnet - unencrypted shell",
    [80] = "HTTP - unencrypted web",
    [5555] = "ADB - Android Debug Bridge"
  }

  local warning = insecure_ports[port.number]
  if warning then
    table.insert(result, "[!] Insecure service: " .. warning)
  end

  if port.version and port.version.name then
    table.insert(result, "[+] Service: " .. port.version.name)
  end

  table.insert(result, "[!] Mobile devices should use encrypted protocols only")

  return stdnse.format_output(true, result)
end
