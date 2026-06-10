local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Provides detailed information about open ports and services.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Port Information")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: " .. port.protocol)
  table.insert(result, "State: " .. port.state)

  if port.service then
    table.insert(result, "Service: " .. (port.service.name or "unknown"))
    table.insert(result, "Product: " .. (port.service.product or "unknown"))
    table.insert(result, "Version: " .. (port.service.version or "unknown"))
  end

  local well_known = {
    [21] = "FTP - File Transfer Protocol",
    [22] = "SSH - Secure Shell",
    [23] = "Telnet",
    [25] = "SMTP - Mail Transfer",
    [53] = "DNS - Domain Name System",
    [80] = "HTTP - Web Server",
    [110] = "POP3 - Mail Retrieval",
    [143] = "IMAP - Mail Access",
    [443] = "HTTPS - Secure Web",
    [993] = "IMAPS - Secure IMAP",
    [995] = "POP3S - Secure POP3",
    [3306] = "MySQL Database",
    [3389] = "RDP - Remote Desktop",
    [5432] = "PostgreSQL Database",
    [8080] = "HTTP Alternate"
  }

  local info = well_known[port.number]
  if info then
    table.insert(result, "Description: " .. info)
  end

  return stdnse.format_output(true, result)
end
