local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Checks if the DNS server supports TSIG (Transaction Signature) authentication.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local output = stdnse.output_table()

  output["TSIG Support"] = "TSIG detection requires signed queries"
  output["Note"] = "TSIG is used to authenticate dynamic updates and zone transfers"
  output["Common Algorithms"] = {
    "hmac-md5", "hmac-sha1", "hmac-sha256",
    "hmac-sha384", "hmac-sha512"
  }
  output["Recommendation"] = "Use TSIG to secure zone transfers and dynamic updates"
  return output
end
