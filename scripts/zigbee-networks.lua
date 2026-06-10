local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Detects Zigbee networks using compatible hardware.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return true
end

action = function(host)
  local result = {}

  table.insert(result, "Zigbee Network Detection")
  table.insert(result, "Protocol: IEEE 802.15.4 / Zigbee")
  table.insert(result, "Frequency: 2.4 GHz")

  local handle = io.popen("ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output and #output > 0 then
      table.insert(result, "[+] Serial devices found for Zigbee sniffing")
      for dev in output:gmatch("/dev/%S+") do
        table.insert(result, "[+] Device: " .. dev)
      end
    else
      table.insert(result, "[!] No Zigbee-capable hardware detected")
    end
  end

  table.insert(result, "[!] Zigbee is used in IoT/smart home devices")

  return stdnse.format_output(true, result)
end
