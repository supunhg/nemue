local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Detects Bluetooth devices in range.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return true
end

action = function(host)
  local result = {}

  table.insert(result, "Bluetooth Device Detection")

  local handle = io.popen("hcitool scan 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output then
      local count = 0
      for addr, name in output:gmatch("(%S+%s%S+%s%S+%s%S+%s%S+%s%S+)%s+(.+)") do
        count = count + 1
        table.insert(result, "[+] Device: " .. addr .. " - " .. name)
      end
      if count == 0 then
        for addr in output:gmatch("(%S+%s%S+%s%S+%s%S+%s%S+%s%S+)") do
          count = count + 1
          table.insert(result, "[+] Device: " .. addr)
        end
      end
      table.insert(result, "[+] Devices found: " .. count)
    end
  end

  return stdnse.format_output(true, result)
end
