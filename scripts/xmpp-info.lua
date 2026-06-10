local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts XMPP (Jabber) service information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5222, "xmpp")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "XMPP Service Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: XMPP/Jabber")
  table.insert(result, "Default port: 5222 (client), 5269 (server)")
  port.version.name = "xmpp"
  port.version.product = "XMPP"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
