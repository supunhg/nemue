local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts Consul service discovery information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(8500, "consul")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "HashiCorp Consul Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "HTTP API: http://" .. host.ip .. ":8500/")
  table.insert(result, "Default port: 8500 (HTTP), 8600 (DNS)")
  port.version.name = "consul"
  port.version.product = "Consul"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
