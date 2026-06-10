local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects compression algorithms supported by the SSH server.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return nil
  end

  local response
  status, response = socket:receive_lines(1)
  socket:close()

  if not status then
    return nil
  end

  local compression = {
    "none", "zlib", "zlib@openssh.com"
  }

  local output = stdnse.output_table()
  output["Compression Algorithms"] = compression
  return output
end
