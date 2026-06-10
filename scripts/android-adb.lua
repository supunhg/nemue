local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects Android ADB (Android Debug Bridge) services.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5555, "adb")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Android ADB Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local cnxn = "CNXN\x00\x00\x00\x01\x00\x10\x00\x00\x07\x00\x00\x00\x32\x02\x00\x00\xbc\xb1\xa7\xb1host::\x00"

  socket:send(cnxn)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    if response:find("CNXN") then
      table.insert(result, "[!] ADB service open and accepting connections")
      table.insert(result, "[!] CRITICAL: Android Debug Bridge exposed")
      table.insert(result, "[!] Allows remote shell access to device")
    end
  end

  port.version.name = "adb"
  port.version.product = "Android Debug Bridge"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
