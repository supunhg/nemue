local nmap = require "nmap"
local stdnse = require "stdnse"

description = [[
Enumerates Bluetooth services on detected devices.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

hostrule = function(host)
  return true
end

action = function(host)
  local result = {}

  table.insert(result, "Bluetooth Service Enumeration")

  local handle = io.popen("sdptool browse local 2>/dev/null")
  if handle then
    local output = handle:read("*a")
    handle:close()

    if output then
      local count = 0
      for service in output:gmatch("Service Name: (%S+)") do
        count = count + 1
        table.insert(result, "[+] Service: " .. service)
      end
      table.insert(result, "[+] Local services found: " .. count)
    end
  end

  return stdnse.format_output(true, result)
end
