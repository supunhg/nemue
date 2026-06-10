local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for weak SSH host keys.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

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
    table.insert(result, "SSH Weak Key Check")
    table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

    if response:match("SSH") then
      local version = response:match("SSH[%-%d]+%.%d+")
      if version then
        table.insert(result, "Protocol: " .. version)
      end

      if response:match("OpenSSH") then
        local ossh = response:match("OpenSSH[_%s]+(%d+%.%d+)")
        if ossh then
          table.insert(result, "OpenSSH version: " .. ossh)
        end
      end
    end

    table.insert(result, "Note: Key strength analysis requires host key exchange")
  end

  socket:close()
  return stdnse.format_output(true, result)
end
