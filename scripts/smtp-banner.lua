local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts SMTP banner and supported extensions.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(25, "smtp")

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
    table.insert(result, "SMTP Banner Extraction")
    table.insert(result, "Banner: " .. response:gsub("\r?\n$", ""))

    socket:send("EHLO test\r\n")
    local ehlo
    status, ehlo = socket:receive_lines(1)
    if status and ehlo then
      table.insert(result, "EHLO response: " .. ehlo:gsub("\r?\n$", ""))
    end
  end

  socket:close()
  return stdnse.format_output(true, result)
end
