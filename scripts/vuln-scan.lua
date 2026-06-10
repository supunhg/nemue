local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Performs basic vulnerability scanning on detected services.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Vulnerability Scan")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local vuln_checks = {
    {port = 21, name = "FTP", risk = "Anonymous login possible"},
    {port = 23, name = "Telnet", risk = "Unencrypted protocol"},
    {port = 80, name = "HTTP", risk = "Unencrypted web traffic"},
    {port = 445, name = "SMB", risk = "SMB vulnerabilities"},
    {port = 3389, name = "RDP", risk = "BlueKeep (CVE-2019-0708)"},
    {port = 5900, name = "VNC", risk = "VNC without authentication"},
    {port = 27017, name = "MongoDB", risk = "Unauthenticated access"},
    {port = 6379, name = "Redis", risk = "Unauthenticated access"},
    {port = 9200, name = "Elasticsearch", risk = "Unauthenticated access"},
    {port = 11211, name = "Memcached", risk = "Amplification attack vector"}
  }

  for _, check in ipairs(vuln_checks) do
    if port.number == check.port then
      table.insert(result, "[!] " .. check.name .. ": " .. check.risk)
    end
  end

  if port.version and port.version.version then
    table.insert(result, "[+] Version: " .. port.version.version)
  end

  table.insert(result, "[!] Manual verification recommended")

  return stdnse.format_output(true, result)
end
