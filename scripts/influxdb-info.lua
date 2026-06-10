local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts InfluxDB time-series database information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(8086, "influxdb")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "InfluxDB Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "HTTP API: http://" .. host.ip .. ":8086/")
  table.insert(result, "Default port: 8086/TCP")
  table.insert(result, "Security: Check for authentication requirements")
  port.version.name = "influxdb"
  port.version.product = "InfluxDB"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
