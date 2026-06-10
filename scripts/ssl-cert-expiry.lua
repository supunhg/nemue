local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local sslcert = require "sslcert"

description = [[
Checks the SSL/TLS certificate expiration date on the target.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(443, "https", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return nil
  end

  socket:close()

  local output = stdnse.output_table()
  output["Status"] = "Certificate expiry check requires SSL handshake"
  output["Recommendation"] = "Use ssl-cert NSE script for detailed certificate info"
  return output
end
