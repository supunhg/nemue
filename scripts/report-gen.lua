local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local io = require "io"

description = [[
Generates scan reports in various formats.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = function(host, port)
  return port.state == "open"
end

action = function(host, port)
  local result = {}

  table.insert(result, "Report Generation")
  table.insert(result, "Target: " .. host.ip .. ":" .. port.number)

  local report = {
    host = host.ip,
    port = port.number,
    protocol = port.protocol,
    state = port.state,
    service = port.service and port.service.name or "unknown",
    timestamp = os.date("%Y-%m-%d %H:%M:%S")
  }

  local report_file = io.open("/tmp/nemue-report.json", "a")
  if report_file then
    local json = string.format('{"host":"%s","port":%d,"protocol":"%s","state":"%s","service":"%s","time":"%s"}\n',
      report.host, report.port, report.protocol, report.state, report.service, report.timestamp)
    report_file:write(json)
    report_file:close()
    table.insert(result, "[+] Report entry written")
  end

  table.insert(result, "[!] Full reporting available with --report flag")

  return stdnse.format_output(true, result)
end
