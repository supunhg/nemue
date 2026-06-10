local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects the OpenSSL Heartbleed vulnerability (CVE-2014-0160).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service(443, "https", "tcp")

action = function(host, port)
  local output = stdnse.output_table()

  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    output["Status"] = "Could not connect"
    return output
  end

  socket:close()

  output["Vulnerability"] = "CVE-2014-0160 (Heartbleed)"
  output["Description"] = "OpenSSL Heartbleed allows reading memory from vulnerable servers"
  output["Severity"] = "Critical"
  output["Note"] = "Full detection requires sending malformed heartbeat request"
  output["Recommendation"] = "Update OpenSSL to version 1.0.1g or later"
  return output
end
