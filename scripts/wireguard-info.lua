local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts WireGuard VPN service information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(51820, "wireguard")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "WireGuard VPN Detected")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: WireGuard")
  table.insert(result, "Default port: 51820/UDP")
  port.version.name = "wireguard"
  port.version.product = "WireGuard"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
