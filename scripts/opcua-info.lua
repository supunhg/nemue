local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts OPC UA (Unified Architecture) server information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(4840, "opcua")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "OPC UA Information")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: OPC UA (Unified Architecture)")
  table.insert(result, "Default port: 4840")
  table.insert(result, "Industry: Industrial Automation/SCADA")

  local hello = string.char(
    0x48, 0x45, 0x4c, 0x46,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  )

  socket:send(hello)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] OPC UA server responding")
    if #response >= 4 then
      local msg_type = response:sub(1, 4)
      if msg_type == "ACKF" or msg_type == "ERRF" then
        table.insert(result, "[+] OPC UA protocol confirmed")
      end
    end
  end

  port.version.name = "opcua"
  port.version.product = "OPC UA Server"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
