local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts Docker API information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(2375, "docker")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Docker API Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "API: Docker Engine API")
  table.insert(result, "Default port: 2375 (unencrypted), 2376 (TLS)")
  table.insert(result, "WARNING: Unencrypted Docker API allows container management")
  port.version.name = "docker"
  port.version.product = "Docker"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
