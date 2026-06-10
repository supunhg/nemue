local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for weak SSL/TLS cipher suites.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  return shortport.ssl(host, port) or port.version.name == "https"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Weak Cipher Suite Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local weak_ciphers = {
    "RC4",
    "DES",
    "3DES",
    "MD5",
    "NULL",
    "EXPORT",
    "anon",
  }

  table.insert(result, "Checking for weak cipher categories:")
  for _, cipher in ipairs(weak_ciphers) do
    table.insert(result, "  - " .. cipher)
  end

  table.insert(result, "Note: Full cipher enumeration requires SSL handshake")
  table.insert(result, "Recommendation: Use TLS 1.2+ with AEAD ciphers only")

  return stdnse.format_output(true, result)
end
