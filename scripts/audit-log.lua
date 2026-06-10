local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local io = require "io"

description = [[
Logs scan results to an audit file for compliance purposes.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Audit Logging")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local timestamp = os.date("%Y-%m-%d %H:%M:%S")
  local log_entry = string.format("[%s] %s:%d %s %s",
    timestamp, host.ip, port.number,
    port.protocol, port.state)

  if port.service then
    log_entry = log_entry .. " " .. (port.service.name or "")
  end

  local logfile = io.open("/tmp/nemue-audit.log", "a")
  if logfile then
    logfile:write(log_entry .. "\n")
    logfile:close()
    table.insert(result, "[+] Audit entry logged")
  else
    table.insert(result, "[!] Could not write to audit log")
  end

  table.insert(result, "[!] Audit logs support compliance requirements")

  return stdnse.format_output(true, result)
end
