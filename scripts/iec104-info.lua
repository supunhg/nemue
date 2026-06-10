local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts IEC 60870-5-104 SCADA protocol information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(2404, "iec104")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "IEC 60870-5-104 Information")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: IEC 60870-5-104 (SCADA)")
  table.insert(result, "Default port: 2404")
  table.insert(result, "Industry: Power/Utility SCADA")

  local startdt = string.char(0x68, 0x04, 0x07, 0x00, 0x00, 0x00)

  socket:send(startdt)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    if #response >= 6 then
      local start = response:byte(1)
      if start == 0x68 then
        table.insert(result, "[+] IEC 104 service responding")
        local ctrl = response:byte(3)
        if ctrl == 0x0B then
          table.insert(result, "[+] STARTDT actcon received")
          table.insert(result, "[!] SCADA RTU/IED detected")
        end
      end
    end
  end

  port.version.name = "iec104"
  port.version.product = "IEC 60870-5-104"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
