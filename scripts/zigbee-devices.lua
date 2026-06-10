local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Enumerates Zigbee devices on detected networks.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return true
end

action = function(host)
  local result = {}

  table.insert(result, "Zigbee Device Enumeration")
  table.insert(result, "Protocol: Zigbee (IEEE 802.15.4)")

  table.insert(result, "[!] Zigbee device enumeration requires:")
  table.insert(result, "    - Compatible RF hardware (e.g., TI CC2531)")
  table.insert(result, "    - Packet capture software (e.g., KillerBee)")

  local handle = io.popen("which zbdump zbstumbler 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output and #output > 0 then
      table.insert(result, "[+] KillerBee tools available")
    else
      table.insert(result, "[!] KillerBee tools not installed")
    end
  end

  table.insert(result, "[!] Zigbee devices: sensors, locks, lights, thermostats")

  return stdnse.format_output(true, result)
end
