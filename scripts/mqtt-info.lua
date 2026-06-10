local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts MQTT (Message Queuing Telemetry Transport) information.
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

  table.insert(result, "MQTT Service Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: MQTT (IoT Messaging)")
  table.insert(result, "Default port: 1883/TCP")
  table.insert(result, "Secure port: 8883 (MQTTS)")
  table.insert(result, "Security: Check for anonymous access")
  port.version.name = "mqtt"
  port.version.product = "MQTT"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
