local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts DICOM medical imaging protocol information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(11112, "dicom")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "DICOM Service Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: DICOM (Medical Imaging)")
  table.insert(result, "Default port: 11112")
  table.insert(result, "Security: Check for authentication requirements")
  port.version.name = "dicom"
  port.version.product = "DICOM"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
