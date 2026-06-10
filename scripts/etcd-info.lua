local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts etcd key-value store information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(2379, "etcd")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "etcd Key-Value Store Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "HTTP API: http://" .. host.ip .. ":2379/")
  table.insert(result, "Default port: 2379 (client), 2380 (peer)")
  table.insert(result, "WARNING: Check for unauthorized API access")
  port.version.name = "etcd"
  port.version.product = "etcd"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
