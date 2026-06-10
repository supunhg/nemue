local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Performs DNS cache snooping to determine recently queried domains.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local domains = {
    "www.google.com", "www.facebook.com", "www.youtube.com",
    "www.twitter.com", "www.amazon.com", "www.microsoft.com",
    "www.apple.com", "www.netflix.com", "www.github.com",
    "www.wikipedia.org"
  }

  local cached = {}
  for _, domain in ipairs(domains) do
    local status, response = dns.query(domain, {host = host.ip, port = port.number, dtype = "A", recurse = false})
    if status and response then
      table.insert(cached, domain .. " (cached)")
    end
  end

  local output = stdnse.output_table()
  output["Cached Domains"] = cached
  output["Note"] = "Domains in cache indicate recent queries from this resolver"
  return output
end
