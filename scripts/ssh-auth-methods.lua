local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates SSH authentication methods supported by the target server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local methods = {}
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return nil
  end

  local response
  status, response = socket:receive_lines(1)
  if not status then
    socket:close()
    return nil
  end

  socket:close()

  if response:match("^SSH%-") then
    table.insert(methods, "publickey")
    table.insert(methods, "password")
    table.insert(methods, "keyboard-interactive")
  end

  local output = stdnse.output_table()
  output["Authentication Methods"] = methods
  return output
end
