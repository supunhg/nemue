local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates Siemens S7 communication protocol on PLCs.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(102, "s7comm")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "S7comm Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: S7comm (Siemens Industrial)")

  local tpkt = string.char(0x03, 0x00, 0x00, 0x16)
  local cotp = string.char(0x11, 0xe0, 0x00, 0x00, 0x00, 0x01, 0x00, 0xc1, 0x02, 0x01, 0x00, 0xc2, 0x02, 0x01, 0x02, 0xc0, 0x01, 0x09)

  socket:send(tpkt .. cotp)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] S7comm service responding")
    if #response >= 22 then
      table.insert(result, "[+] PLC detected")
      table.insert(result, "[!] Siemens S7 PLC commonly used in industrial control")
    end
  end

  port.version.name = "s7comm"
  port.version.product = "Siemens S7"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
