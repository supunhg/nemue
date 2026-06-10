local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Analyzes WiFi security settings of detected access points.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return host.interface ~= nil
end

action = function(host)
  local result = {}

  table.insert(result, "WiFi Security Analysis")
  table.insert(result, "Interface: " .. (host.interface or "unknown"))

  local handle = io.popen("iwlist " .. (host.interface or "wlan0") .. " scan 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output then
      for essid, encryption in output:gmatch('ESSID:"([^"]+)".-Encryption key:(%S+)') do
        if encryption == "off" then
          table.insert(result, "[!] OPEN NETWORK: " .. essid)
        else
          table.insert(result, "[+] Secured: " .. essid)
        end
      end

      for wpa in output:gmatch("WPA[%s]+Version (%d+)") do
        table.insert(result, "[+] WPA version: " .. wpa)
      end
    end
  end

  return stdnse.format_output(true, result)
end
