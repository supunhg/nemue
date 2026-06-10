local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts RabbitMQ service information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5672, "amqp")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "RabbitMQ/AMQP Service Detected")
    table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
    table.insert(result, "Protocol: AMQP")
    table.insert(result, "Management UI: http://" .. host.ip .. ":15672/")
    port.version.name = "amqp"
    port.version.product = "RabbitMQ"
    nmap.set_port_version(host, port)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
