local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts SonarQube code quality service information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(9000, "sonarqube")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "SonarQube Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Web UI: http://" .. host.ip .. ":9000/")
  table.insert(result, "Default credentials: admin/admin")
  port.version.name = "sonarqube"
  port.version.product = "SonarQube"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
