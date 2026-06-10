local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts Jenkins CI/CD service information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(8080, "jenkins")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Jenkins CI/CD Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Web UI: http://" .. host.ip .. ":8080/")
  table.insert(result, "Default port: 8080/TCP")
  table.insert(result, "Security: Check for Script Console exposure")
  port.version.name = "jenkins"
  port.version.product = "Jenkins"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
