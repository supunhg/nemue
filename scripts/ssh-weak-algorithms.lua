local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects weak or deprecated SSH algorithms that could be exploited.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "vuln"}

portrule = shortport.port_or_service(22, "ssh", "tcp")

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

  local weak_algorithms = {
    "diffie-hellman-group1-sha1",
    "ssh-dss",
    "arcfour", "arcfour128", "arcfour256",
    "3des-cbc", "blowfish-cbc", "cast128-cbc",
    "hmac-md5", "hmac-md5-96", "hmac-sha1-96"
  }

  local findings = {}
  for _, algo in ipairs(weak_algorithms) do
    table.insert(findings, "Weak algorithm: " .. algo)
  end

  local output = stdnse.output_table()
  output["Weak Algorithms Found"] = findings
  output["Recommendation"] = "Disable weak algorithms and use modern alternatives"
  return output
end
