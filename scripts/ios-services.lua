local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects iOS-related services and management interfaces.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(62078, "iphone-sync")

action = function(host, port)
  local result = {}

  table.insert(result, "iOS Services Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local sock = nmap.new_socket()
  local status, err = sock:connect(host, port)

  if status then
    table.insert(result, "[+] iOS sync service detected")
    table.insert(result, "[!] Device may be jailbroken or in developer mode")
  end

  local mdm_ports = {443, 1640, 2195, 2196, 5223}
  for _, p in ipairs(mdm_ports) do
    local s = nmap.new_socket()
    if s:connect(host.ip, p) then
      table.insert(result, "[+] iOS-related port open: " .. p)
    end
    s:close()
  end

  sock:close()
  return stdnse.format_output(true, result)
end
