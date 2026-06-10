local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects SIP user agent and server information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(5060, "sip")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "SIP User Agent Detection")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local options = "OPTIONS sip:" .. host.ip .. " SIP/2.0\r\n"
  options = options .. "Via: SIP/2.0/UDP " .. host.ip .. "\r\n"
  options = options .. "To: <sip:" .. host.ip .. ">\r\n"
  options = options .. "From: <sip:test@" .. host.ip .. ">\r\n"
  options = options .. "Call-ID: agenttest@" .. host.ip .. "\r\n"
  options = options .. "CSeq: 1 OPTIONS\r\n\r\n"

  socket:send(options)
  local response
  status, response = socket:receive_lines(1)

  if status and response then
    local server = response:match("Server: (%C+)")
    if server then
      table.insert(result, "Server: " .. server)
    end
    local ua = response:match("User%-Agent: (%C+)")
    if ua then
      table.insert(result, "User-Agent: " .. ua)
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
