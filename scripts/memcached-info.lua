local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts information from a Memcached server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(11211, "memcache")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  socket:send("version\r\n")
  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "Memcached service detected")
    local ver = response:match("VERSION (%S+)")
    if ver then
      table.insert(result, "Version: " .. ver)
    end
    table.insert(result, "Host: " .. host.ip)
    table.insert(result, "Port: " .. port.number)
    port.version.name = "memcache"
    port.version.product = "Memcached"
    nmap.set_port_version(host, port)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
