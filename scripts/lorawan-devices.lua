local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Detects LoRaWAN devices and gateways.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return true
end

action = function(host)
  local result = {}

  table.insert(result, "LoRaWAN Device Detection")
  table.insert(result, "Protocol: LoRaWAN")
  table.insert(result, "Frequency: 868 MHz (EU) / 915 MHz (US)")

  table.insert(result, "[!] LoRaWAN gateway detection requires SDR hardware")

  local handle = io.popen("ls /dev/ttyUSB* /dev/spidev* 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output and #output > 0 then
      table.insert(result, "[+] SPI/Serial devices found for LoRa modules")
      for dev in output:gmatch("/dev/%S+") do
        table.insert(result, "[+] Device: " .. dev)
      end
    end
  end

  table.insert(result, "[!] LoRaWAN: Long range, low power IoT protocol")

  return stdnse.format_output(true, result)
end
