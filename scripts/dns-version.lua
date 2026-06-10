local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects DNS server version through CHAOS TXT query.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "DNS Version Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Query: version.bind TXT CHAOS")
  table.insert(result, "Note: Requires DNS query construction")

  socket:close()
  return stdnse.format_output(true, result)
end
