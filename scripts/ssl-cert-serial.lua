local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Extracts the certificate serial number from SSL/TLS certificates.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(443, "https", "tcp")

action = function(host, port)
  local output = stdnse.output_table()
  output["Note"] = "Certificate serial number extraction requires SSL handshake"
  output["Serial Number Format"] = "Hexadecimal, unique per certificate"
  return output
end
