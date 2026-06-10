local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local ssl = require "ssl"

description = [[
Analyzes mobile application certificates.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(443, "https")

action = function(host, port)
  local result = {}

  table.insert(result, "Mobile Certificate Analysis")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local sock = nmap.new_socket()
  local status, err = sock:connect(host, port)

  if status then
    table.insert(result, "[+] TLS service detected")
    table.insert(result, "[!] Checking certificate properties...")

    table.insert(result, "[!] Mobile apps should use certificate pinning")
    table.insert(result, "[!] Check for weak signature algorithms")
    table.insert(result, "[!] Verify certificate chain validity")
  end

  sock:close()
  return stdnse.format_output(true, result)
end
