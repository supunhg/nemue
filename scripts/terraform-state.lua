local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Detects exposed Terraform state files.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
  local result = {}

  table.insert(result, "Terraform State Detection")
  table.insert(result, "Target: " .. host.ip)

  local paths = {
    "/terraform.tfstate",
    "/terraform.tfstate.backup",
    "/.terraform/",
    "/state/terraform.tfstate"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[!] Terraform state file exposed: " .. path)
    end
  end

  table.insert(result, "[!] Terraform state contains all infrastructure secrets")

  return stdnse.format_output(true, result)
end
