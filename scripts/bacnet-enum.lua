local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates BACnet building automation devices and services.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(47808, "bacnet")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "BACnet Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: BACnet (Building Automation)")
  table.insert(result, "Default port: 47808/udp")

  local who_is = string.char(
    0x81, 0x0b, 0x00, 0x11,
    0x01, 0x00, 0x00, 0x00,
    0x00, 0x22, 0x00, 0x60,
    0x00, 0xff, 0xff, 0x00
  )

  socket:send(who_is)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] BACnet device responding")
    table.insert(result, "[+] Device count: 1 or more")
    table.insert(result, "[!] Building automation system detected")
  end

  socket:close()
  return stdnse.format_output(true, result)
end
