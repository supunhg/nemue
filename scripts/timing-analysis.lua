local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects network latency and timing anomalies that may indicate interception.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open" and port.protocol == "tcp"
end

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "Timing Analysis")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local times = {}
  for i = 1, 3 do
    local start = nmap.clock_ms()
    socket:send("PING\r\n")
    local response
    status, response = socket:receive()
    local elapsed = nmap.clock_ms() - start
    table.insert(times, elapsed)
  end

  local avg = 0
  for _, t in ipairs(times) do
    avg = avg + t
  end
  avg = avg / #times

  table.insert(result, string.format("[+] Average response time: %.2f ms", avg))

  if avg > 500 then
    table.insert(result, "[!] High latency detected - possible network issues")
  end

  socket:close()
  return stdnse.format_output(true, result)
end
