local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts MinIO object storage information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(9000, "minio")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "MinIO Object Storage Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "API: http://" .. host.ip .. ":9000/")
  table.insert(result, "Console: http://" .. host.ip .. ":9001/")
  table.insert(result, "Default credentials: minioadmin/minioadmin")
  port.version.name = "minio"
  port.version.product = "MinIO"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
