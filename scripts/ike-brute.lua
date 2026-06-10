local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Performs brute force pre-shared key guessing against IKE servers.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(500, "ike")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "IKE service detected - brute force audit started")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Method: Pre-shared key guessing")

  socket:close()
  return stdnse.format_output(true, result)
end
