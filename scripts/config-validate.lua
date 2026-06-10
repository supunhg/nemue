local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local http = require "http"

description = [[
Validates service configurations against best practices.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Configuration Validation")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local validations = {}

  if port.number == 80 then
    local response = http.get(host, port, "/")
    if response then
      if response.header and response.header["server"] then
        table.insert(validations, "WARN: Server header exposed: " .. response.header["server"])
      end
      if response.header and not response.header["x-frame-options"] then
        table.insert(validations, "WARN: Missing X-Frame-Options header")
      end
      if response.header and not response.header["content-security-policy"] then
        table.insert(validations, "WARN: Missing Content-Security-Policy header")
      end
    end
  end

  if port.number == 22 then
    table.insert(validations, "INFO: Verify SSH uses key-based auth only")
    table.insert(validations, "INFO: Verify SSH protocol version 2")
  end

  if #validations > 0 then
    for _, v in ipairs(validations) do
      table.insert(result, "[*] " .. v)
    end
  else
    table.insert(result, "[+] No configuration issues found")
  end

  return stdnse.format_output(true, result)
end
