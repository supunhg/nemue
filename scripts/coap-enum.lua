local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates CoAP (Constrained Application Protocol) services on IoT devices.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5683, "coap")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "CoAP Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: CoAP (Constrained Application Protocol)")
  table.insert(result, "Default port: 5683/udp")

  local coap_get = string.char(
    0x44, 0x01, 0x00, 0x01,
    0x6e, 0x65, 0x6d, 0x75,
    0xb5, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f, 0x77, 0x6e,
    0x04, 0x63, 0x6f, 0x72, 0x65
  )

  socket:send(coap_get)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] CoAP service responding")
    if #response >= 4 then
      local version = response:byte(1) >> 6
      local msg_type = (response:byte(1) >> 4) & 0x03
      table.insert(result, "[+] CoAP version: " .. (version + 1))
      table.insert(result, "[+] IoT device detected")
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
