local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates EtherNet/IP devices on industrial networks.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(44818, "enip")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "EtherNet/IP Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: EtherNet/IP (Industrial)")

  local list_identity = string.char(
    0x63, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x01, 0x00, 0x00, 0x00
  )

  socket:send(list_identity)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] EtherNet/IP device responding")
    if #response >= 28 then
      local cmd = response:byte(1) + (response:byte(2) * 256)
      if cmd == 0x0063 then
        table.insert(result, "[+] List Identity response received")
      end
    end
    table.insert(result, "[!] CIP-based industrial protocol detected")
  end

  port.version.name = "enip"
  port.version.product = "EtherNet/IP"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
