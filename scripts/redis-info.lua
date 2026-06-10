local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts information from a Redis server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(6379, "redis")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  socket:send("INFO server\r\n")
  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "Redis Information:")
    local ver = response:match("redis_version:(%S+)")
    if ver then
      table.insert(result, "Version: " .. ver)
    end
    local mode = response:match("redis_mode:(%S+)")
    if mode then
      table.insert(result, "Mode: " .. mode)
    end
    local os = response:match("os:(%S+)")
    if os then
      table.insert(result, "OS: " .. os)
    end
    port.version.name = "redis"
    port.version.product = "Redis"
    nmap.set_port_version(host, port)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
