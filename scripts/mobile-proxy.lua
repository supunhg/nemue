local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects mobile proxy configurations and services.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.protocol == "tcp" and (port.number == 8080 or port.number == 3128 or port.number == 8888 or port.number == 1080)
end

action = function(host, port)
  local result = {}

  table.insert(result, "Mobile Proxy Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local proxy_types = {
    [8080] = "HTTP Proxy",
    [3128] = "Squid Proxy",
    [8888] = "Alternative Proxy",
    [1080] = "SOCKS Proxy"
  }

  local proxy_type = proxy_types[port.number]
  if proxy_type then
    table.insert(result, "[+] Proxy service: " .. proxy_type)
  end

  table.insert(result, "[!] Mobile proxies can intercept and modify traffic")

  return stdnse.format_output(true, result)
end
