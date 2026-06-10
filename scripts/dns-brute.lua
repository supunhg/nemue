local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local dns = require "dns"

description = [[
Performs DNS subdomain brute force enumeration.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "discovery"}

portrule = shortport.port_or_service(53, "dns", "tcp")

action = function(host, port)
  local domain = stdnse.get_script_args("dns-brute.domain") or host.name
  local subdomains = {
    "www", "mail", "ftp", "smtp", "pop", "imap", "ns1", "ns2", "ns3",
    "dns", "dns1", "dns2", "mx", "mx1", "mx2", "webmail", "remote",
    "vpn", "proxy", "gateway", "firewall", "router", "switch", "server",
    "test", "dev", "staging", "beta", "alpha", "demo", "sandbox",
    "api", "app", "portal", "login", "admin", "panel", "console",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "cdn", "static", "media", "img", "images", "assets",
    "blog", "forum", "wiki", "docs", "support", "help",
    "shop", "store", "payment", "billing", "checkout"
  }

  local found = {}
  for _, sub in ipairs(subdomains) do
    local fqdn = sub .. "." .. domain
    local status, response = dns.query(fqdn, {host = host.ip, port = port.number, dtype = "A"})
    if status and response then
      table.insert(found, fqdn .. " -> " .. tostring(response))
    end
  end

  local output = stdnse.output_table()
  output["Domain"] = domain
  output["Subdomains Found"] = found
  output["Total Tested"] = #subdomains
  return output
end
