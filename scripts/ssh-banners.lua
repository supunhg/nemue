local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Grabs and parses the SSH banner from the target server.
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
  local version = banner:match("SSH%-[%d%.]+%-(.+)")
  local comments = banner:match("%((.-)%)")

  local output = stdnse.output_table()
  output["Raw Banner"] = banner
  output["Software Version"] = version or "Unknown"
  output["Comments"] = comments or "None"
  return output
end
