local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for NTP monlist command which can be used for DDoS amplification.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(123, "ntp")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "NTP Monlist Amplification Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Vulnerability: NTP monlist can amplify DDoS attacks")
  table.insert(result, "Affected: ntpd with monlist enabled")
  table.insert(result, "Remediation: Disable monlist or upgrade to ntpd 4.2.7+")

  socket:close()
  return stdnse.format_output(true, result)
end
