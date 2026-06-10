local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts POP3 banner and capabilities.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(110, "pop3")

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
    table.insert(result, "POP3 Banner Extraction")
    table.insert(result, "Banner: " .. response:gsub("\r?\n$", ""))

    socket:send("CAPA\r\n")
    local capa
    status, capa = socket:receive_lines(1)
    if status and capa then
      table.insert(result, "Capabilities: " .. capa:gsub("\r?\n$", ""))
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
