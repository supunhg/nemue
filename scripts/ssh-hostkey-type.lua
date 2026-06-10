local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects the SSH host key type used by the target server.
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

  local key_types = {
    "ssh-rsa", "ssh-dss", "ssh-ed25519", "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521"
  }

  local output = stdnse.output_table()
  output["Banner"] = response:gsub("\r?\n$", "")
  output["Likely Key Types"] = key_types
  return output
end
