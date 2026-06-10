local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Enumerates AWS S3 buckets via metadata service and DNS.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
  local result = {}

  table.insert(result, "AWS S3 Bucket Enumeration")
  table.insert(result, "Target: " .. host.ip)

  local response = http.get(host, port, "/latest/meta-data/")

  if response and response.status == 200 then
    table.insert(result, "[!] AWS metadata service accessible")
    table.insert(result, "[!] Potential SSRF to S3 via metadata")
  end

  local buckets = {"backup", "data", "logs", "assets", "uploads", "config", "secrets", "admin", "public", "private"}

  for _, bucket in ipairs(buckets) do
    local bucket_url = "/" .. bucket
    local resp = http.get(host, port, bucket_url)
    if resp and resp.status ~= 404 then
      table.insert(result, "[+] Potential bucket path: /" .. bucket .. " (HTTP " .. resp.status .. ")")
    end
  end

  table.insert(result, "[!] Check for S3 bucket misconfigurations")

  return stdnse.format_output(true, result)
end
