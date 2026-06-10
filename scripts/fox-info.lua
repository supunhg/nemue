local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts FOX protocol information from building automation systems.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(1911, "fox")

action = function(host, port)
  local socket = nmap.new_socket()
  local result = {}
  local status, err = socket:connect(host, port)

  if not status then
    stdnse.debug1("Could not connect: %s", err)
    return nil
  end

  table.insert(result, "FOX Protocol Information")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)
  table.insert(result, "Protocol: FOX (Tridium Niagara)")
  table.insert(result, "Default port: 1911")
  table.insert(result, "Industry: Building Automation")

  local fox_hello = "fox a 0 -1 fox hello\n" ..
    "domain: fox\n" ..
    "type: fox\n" ..
    "version: 0.0.1\n"

  socket:send(fox_hello)
  local response
  status, response = socket:receive()

  if status and response and #response > 0 then
    table.insert(result, "[+] FOX protocol service responding")
    if response:find("fox") then
      table.insert(result, "[+] Tridium Niagara platform detected")
      table.insert(result, "[!] Building automation system found")
    end
  end

  port.version.name = "fox"
  port.version.product = "Tridium Niagara FOX"
  nmap.set_port_version(host, port)

  socket:close()
  return stdnse.format_output(true, result)
end
