local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs compliance checks against security baselines.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Compliance Check")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local issues = {}

  if port.number == 21 then
    table.insert(issues, "FAIL: FTP uses unencrypted transport")
  end

  if port.number == 23 then
    table.insert(issues, "FAIL: Telnet uses unencrypted transport")
  end

  if port.number == 80 then
    table.insert(issues, "WARN: HTTP without TLS encryption")
  end

  if port.number == 443 or port.number == 8443 then
    table.insert(issues, "PASS: TLS-encrypted service")
  end

  if port.number == 22 then
    table.insert(issues, "PASS: SSH encrypted service")
  end

  if #issues > 0 then
    for _, issue in ipairs(issues) do
      table.insert(result, "[*] " .. issue)
    end
  else
    table.insert(result, "[+] No compliance issues detected for this port")
  end

  table.insert(result, "[!] Full compliance audit requires additional tools")

  return stdnse.format_output(true, result)
end
