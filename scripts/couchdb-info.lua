local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts information from a CouchDB server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5984, "couchdb")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "CouchDB service detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Default port: 5984")
  table.insert(result, "Admin interface: http://" .. host.ip .. ":5984/_utils/")
  port.version.name = "couchdb"
  port.version.product = "CouchDB"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
