local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Analyzes WiFi channel usage and congestion.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return host.interface ~= nil
end

action = function(host)
  local result = {}

  table.insert(result, "WiFi Channel Analysis")
  table.insert(result, "Interface: " .. (host.interface or "unknown"))

  local handle = io.popen("iwlist " .. (host.interface or "wlan0") .. " scan 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output then
      local channels = {}
      for ch in output:gmatch("Channel:(%d+)") do
        channels[ch] = (channels[ch] or 0) + 1
      end

      for ch, count in pairs(channels) do
        table.insert(result, "[+] Channel " .. ch .. ": " .. count .. " AP(s)")
      end
    end
  end

  return stdnse.format_output(true, result)
end
