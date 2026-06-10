local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects the SSH protocol version and software version.
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

  local banner = response:gsub("\r?\n$", "")
  local proto_version = banner:match("^(SSH%-[%d%.]+)")
  local software = banner:match("SSH%-[%d%.]+%-(.+)$")

  local output = stdnse.output_table()
  output["Banner"] = banner
  output["Protocol Version"] = proto_version or "Unknown"
  output["Software"] = software or "Unknown"
  return output
end
