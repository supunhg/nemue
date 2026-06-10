local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts information from an Elasticsearch server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(9200, "es")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Elasticsearch detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "REST API: http://" .. host.ip .. ":9200/")
  port.version.name = "es"
  port.version.product = "Elasticsearch"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
