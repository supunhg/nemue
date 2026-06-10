local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates MAC algorithms supported by the SSH server.
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

  local macs = {
    "hmac-sha1", "hmac-sha1-96", "hmac-sha2-256", "hmac-sha2-512",
    "hmac-md5", "hmac-md5-96", "hmac-ripemd160",
    "hmac-sha1-etm@openssh.com", "hmac-sha2-256-etm@openssh.com",
    "hmac-sha2-512-etm@openssh.com", "hmac-md5-etm@openssh.com",
    "umac-64@openssh.com", "umac-128@openssh.com"
  }

  local output = stdnse.output_table()
  output["MAC Algorithms"] = macs
  return output
end
