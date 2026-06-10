local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Discovers supported SIP methods on a SIP server.
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

  local options = "OPTIONS sip:" .. host.ip .. " SIP/2.0\r\n"
  options = options .. "Via: SIP/2.0/UDP " .. host.ip .. "\r\n"
  options = options .. "To: <sip:" .. host.ip .. ">\r\n"
  options = options .. "From: <sip:test@" .. host.ip .. ">\r\n"
  options = options .. "Call-ID: test@" .. host.ip .. "\r\n"
  options = options .. "CSeq: 1 OPTIONS\r\n\r\n"

  socket:send(options)
  local response
  status, response = socket:receive_lines(1)

  if status and response then
    table.insert(result, "SIP service detected")
    table.insert(result, "Response: " .. response:sub(1, 80))
    local allow = response:match("Allow: (%C+)")
    if allow then
      table.insert(result, "Allowed methods: " .. allow)
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
