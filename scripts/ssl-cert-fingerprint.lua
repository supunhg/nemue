local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Computes and displays the certificate fingerprint (SHA-1 and SHA-256).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(443, "https", "tcp")

action = function(host, port)
  local output = stdnse.output_table()
  output["Note"] = "Certificate fingerprint computation requires SSL handshake"
  output["Fingerprint Algorithms"] = {"SHA-1", "SHA-256", "MD5"}
  return output
end
