local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Extracts GCP instance metadata information.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
  local result = {}

  table.insert(result, "GCP Metadata Extraction")
  table.insert(result, "Target: " .. host.ip)

  local paths = {
    "/computeMetadata/v1/",
    "/computeMetadata/v1/instance/",
    "/computeMetadata/v1/project/"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[+] GCP metadata endpoint accessible: " .. path)
      table.insert(result, "[!] GCP instance metadata service exposed")
    end
  end

  table.insert(result, "[!] GCP metadata can expose service account tokens")

  return stdnse.format_output(true, result)
end
