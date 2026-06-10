local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates MQTT brokers and topics on IoT networks.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(1883, "mqtt")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "MQTT Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: MQTT (Message Queuing Telemetry Transport)")
  table.insert(result, "Default port: 1883")

  local connect_pkt = string.char(
    0x10, 0x16,
    0x00, 0x04, 0x4d, 0x51, 0x54, 0x54,
    0x04, 0x02, 0x00, 0x3c,
    0x00, 0x0a, 0x6e, 0x65, 0x6d, 0x75, 0x65, 0x73, 0x63, 0x61, 0x6e
  )

  socket:send(connect_pkt)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    local connack = response:byte(1)
    if connack == 0x20 then
      local rc = response:byte(4)
      if rc == 0x00 then
        table.insert(result, "[+] MQTT broker accepting connections")
        table.insert(result, "[!] Broker allows anonymous access")
      else
        table.insert(result, "[+] MQTT broker responded (auth required)")
      end
    end
  end

  port.version.name = "mqtt"
  port.version.product = "MQTT Broker"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
