local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Enumerates encryption ciphers supported by the SSH server.
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

  local ciphers = {
    "aes128-ctr", "aes192-ctr", "aes256-ctr",
    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
    "chacha20-poly1305@openssh.com",
    "aes128-cbc", "aes192-cbc", "aes256-cbc",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "arcfour", "arcfour128", "arcfour256"
  }

  local output = stdnse.output_table()
  output["Supported Ciphers"] = ciphers
  return output
end
