local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts Kubernetes API information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(6443, "kubernetes")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Kubernetes API Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "API: Kubernetes API Server")
  table.insert(result, "Default port: 6443/TCP")
  table.insert(result, "Security: Check for anonymous access")
  port.version.name = "kubernetes"
  port.version.product = "Kubernetes"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
