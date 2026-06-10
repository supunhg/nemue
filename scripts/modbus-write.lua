local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Tests for Modbus write access on industrial devices.
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

  table.insert(result, "Modbus Write Test")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local mbap = string.char(0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01)
  local func_write = string.char(0x05, 0x00, 0x00, 0xFF, 0x00)

  socket:send(mbap .. func_write)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    if #response >= 9 then
      local func_code = response:byte(8)
      if func_code == 0x05 then
        table.insert(result, "[!] Write single coil accepted")
        table.insert(result, "[!] CRITICAL: Device allows write operations")
      elseif func_code >= 0x80 then
        table.insert(result, "[+] Write rejected (exception code)")
      end
    end
  end

  table.insert(result, "[!] Unprotected Modbus writes can disrupt industrial processes")
  socket:close()
  return stdnse.format_output(true, result)
end
