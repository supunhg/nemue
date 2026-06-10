local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Detects WiFi access points using wireless interface information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return host.interface ~= nil
end

action = function(host)
  local result = {}

  table.insert(result, "WiFi Access Point Detection")
  table.insert(result, "Interface: " .. (host.interface or "unknown"))

  local handle = io.popen("iwlist " .. (host.interface or "wlan0") .. " scan 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output then
      local count = 0
      for cell in output:gmatch("Cell %d+") do
        count = count + 1
      end
      table.insert(result, "[+] Access points found: " .. count)

      for essid in output:gmatch('ESSID:"([^"]+)"') do
        table.insert(result, "[+] AP: " .. essid)
      end
    end
  end

  return stdnse.format_output(true, result)
end
