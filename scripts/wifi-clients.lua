local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Detects WiFi clients on wireless networks.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return host.interface ~= nil
end

action = function(host)
  local result = {}

  table.insert(result, "WiFi Client Detection")
  table.insert(result, "Interface: " .. (host.interface or "unknown"))

  local handle = io.popen("iw dev " .. (host.interface or "wlan0") .. " station dump 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output then
      local count = 0
      for station in output:gmatch("Station (%S+)") do
        count = count + 1
        table.insert(result, "[+] Client MAC: " .. station)
      end
      table.insert(result, "[+] Connected clients: " .. count)
    end
  end

  return stdnse.format_output(true, result)
end
