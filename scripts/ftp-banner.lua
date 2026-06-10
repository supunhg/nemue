local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts FTP banner and server information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(21, "ftp")

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
    table.insert(result, "FTP Banner Extraction")
    table.insert(result, "Banner: " .. response:gsub("\r?\n$", ""))
    if response:match("vsFTPd") then
      local ver = response:match("vsFTPd (%d+%.%d+%.%d+)")
      if ver then
        table.insert(result, "Version: vsFTPd " .. ver)
      end
    elseif response:match("ProFTPD") then
      local ver = response:match("ProFTPD (%d+%.%d+%.%d+)")
      if ver then
        table.insert(result, "Version: ProFTPD " .. ver)
      end
    elseif response:match("FileZilla") then
      table.insert(result, "Server: FileZilla Server")
    end
    port.version.name = "ftp"
    nmap.set_port_version(host, port)
  end

  socket:close()
  return stdnse.format_output(true, result)
end
