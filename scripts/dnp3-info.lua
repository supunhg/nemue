local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts DNP3 (Distributed Network Protocol) information from SCADA systems.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(20000, "dnp3")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "DNP3 Information")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: DNP3 (Distributed Network Protocol)")
  table.insert(result, "Industry: SCADA/Industrial Automation")
  table.insert(result, "Default port: 20000")

  local dnp3_request = string.char(0x05, 0x64, 0x05, 0xC0, 0x01, 0x00, 0x00, 0x04, 0x00)

  socket:send(dnp3_request)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] DNP3 service responding")
    if #response >= 10 then
      local start = response:byte(1)
      if start == 0x05 then
        table.insert(result, "[+] Valid DNP3 start byte detected")
        local dst = (response:byte(4) * 256) + response:byte(3)
        local src = (response:byte(6) * 256) + response:byte(5)
        table.insert(result, "[+] Destination address: " .. dst)
        table.insert(result, "[+] Source address: " .. src)
      end
    end
  end

  port.version.name = "dnp3"
  port.version.product = "DNP3"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
