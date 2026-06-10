local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects known FTP server backdoors (e.g., ProFTPD 1.3.3c backdoor).
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "intrusive"}

portrule = shortport.port_or_service(21, "ftp", "tcp")

action = function(host, port)
  local socket = nmap.new_socket()
  local status, err = socket:connect(host, port)
  if not status then
    return nil
  end

  local response
  status, response = socket:receive_lines(1)
  socket:close()

  if not status then
    return nil
  end

  local banner = response:gsub("\r?\n$", "")
  local output = stdnse.output_table()

  local backdoor_patterns = {
    {pattern = "ProFTPD 1%.3%.3c", cve = "CVE-2011-4130", desc = "Known backdoor version"},
    {pattern = "ProFTPD 1%.3%.2", cve = "CVE-2009-3639", desc = "SQL injection vulnerability"},
    {pattern = "vsFTPD 2%.3%.4", cve = "CVE-2011-2523", desc = "Backdoor shell on port 6200"},
  }

  local findings = {}
  for _, bd in ipairs(backdoor_patterns) do
    if banner:match(bd.pattern) then
      table.insert(findings, bd.cve .. ": " .. bd.desc)
    end
  end

  output["Banner"] = banner
  if #findings > 0 then
    output["Backdoors Found"] = findings
    output["Status"] = "VULNERABLE"
  else
    output["Status"] = "No known backdoors detected"
  end
  return output
end
