local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs basic OS detection based on network fingerprinting.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "OS Detection")
  table.insert(result, "Target: " .. host.ip)

  if host.os then
    table.insert(result, "[+] Detected OS: " .. host.os)
  end

  local os_hints = {}

  if port.number == 3389 then
    table.insert(os_hints, "Windows (RDP detected)")
  end

  if port.number == 22 then
    table.insert(os_hints, "Linux/Unix (SSH detected)")
  end

  if port.service and port.service.name == "microsoft-ds" then
    table.insert(os_hints, "Windows (SMB detected)")
  end

  if #os_hints > 0 then
    for _, hint in ipairs(os_hints) do
      table.insert(result, "[+] OS hint: " .. hint)
    end
  else
    table.insert(result, "[!] No OS hints from this port")
  end

  return stdnse.format_output(true, result)
end
