local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Detects exposed Ansible inventory files.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(80, "http")

action = function(host, port)
  local result = {}

  table.insert(result, "Ansible Inventory Detection")
  table.insert(result, "Target: " .. host.ip)

  local paths = {
    "/inventory",
    "/hosts",
    "/ansible.cfg",
    "/playbooks/",
    "/group_vars/",
    "/host_vars/"
  }

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "[!] Ansible file exposed: " .. path)
    end
  end

  table.insert(result, "[!] Ansible inventories may contain credentials")

  return stdnse.format_output(true, result)
end
