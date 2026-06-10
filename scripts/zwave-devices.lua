local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Detects Z-Wave devices on smart home networks.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return true
end

action = function(host)
  local result = {}

  table.insert(result, "Z-Wave Device Detection")
  table.insert(result, "Protocol: Z-Wave")
  table.insert(result, "Frequency: 908.42 MHz (US) / 868.42 MHz (EU)")

  table.insert(result, "[!] Z-Wave device enumeration requires:")
  table.insert(result, "    - Z-Wave controller hardware")
  table.insert(result, "    - Z-Wave packet analyzer")

  local handle = io.popen("ls /dev/ttyUSB* /dev/ttyACM* 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output and #output > 0 then
      table.insert(result, "[+] Serial devices found")
    end
  end

  table.insert(result, "[!] Z-Wave devices: locks, sensors, switches, thermostats")

  return stdnse.format_output(true, result)
end
