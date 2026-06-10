local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts SSH banner and version information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(22, "ssh")

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
    table.insert(result, "SSH Banner Extraction")
    table.insert(result, "Banner: " .. response:gsub("\r?\n$", ""))

    local proto = response:match("SSH%-(%d+%.%d+)")
    if proto then
      table.insert(result, "Protocol: " .. proto)
    end

    local impl = response:match("SSH%d+%.%d+(%S+)")
    if impl then
      table.insert(result, "Implementation: " .. impl)
    end

    port.version.name = "ssh"
    nmap.set_port_version(host, port)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
