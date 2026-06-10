local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts AMQP (Advanced Message Queuing Protocol) broker information.
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

  table.insert(result, "AMQP Information")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: AMQP (Advanced Message Queuing Protocol)")
  table.insert(result, "Default port: 5672")

  local amqp_header = "AMQP\x00\x09\x01"

  socket:send(amqp_header)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] AMQP broker responding")
    if #response >= 8 then
      local proto = response:sub(1, 4)
      if proto == "AMQP" then
        table.insert(result, "[+] AMQP protocol confirmed")
        local major = response:byte(6)
        local minor = response:byte(7)
        table.insert(result, "[+] AMQP version: " .. major .. "." .. minor)
      end
    end
  end

  port.version.name = "amqp"
  port.version.product = "AMQP Broker"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
