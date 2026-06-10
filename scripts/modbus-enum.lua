local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates Modbus devices and function codes on industrial networks.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(502, "modbus")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Modbus Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local mbap = string.char(0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01)
  local func_read = string.char(0x03, 0x00, 0x00, 0x00, 0x01)

  socket:send(mbap .. func_read)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] Modbus service responding")
    if #response >= 9 then
      local func_code = response:byte(8)
      table.insert(result, "[+] Function code: " .. func_code)
      if func_code >= 0x80 then
        table.insert(result, "[!] Error response - function may be restricted")
      else
        table.insert(result, "[+] Read holding registers supported")
      end
    end
    table.insert(result, "[!] Modbus often lacks authentication")
  end

  socket:close()
  return stdnse.format_output(true, result)
end
