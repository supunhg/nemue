local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates DNP3 outstations on SCADA networks.
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

  table.insert(result, "DNP3 Enumeration")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local dnp3_link = string.char(
    0x05, 0x64, 0x05, 0xC0,
    0x01, 0x00, 0x00, 0x04
  )

  socket:send(dnp3_link)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] DNP3 outstation responding")
    if #response >= 10 then
      local func = response:byte(9)
      table.insert(result, "[+] Link layer function: " .. func)
      table.insert(result, "[!] SCADA outstation enumerated")
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
