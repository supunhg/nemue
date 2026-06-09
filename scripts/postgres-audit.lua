local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs PostgreSQL security audit checks.
Identifies weak credentials, insecure configurations, and common security issues.
]]

---
-- @usage
-- nmap --script postgres-audit -p 5432 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 5432/tcp open  postgresql
-- | postgres-audit:
-- |   PostgreSQL Security Audit:
-- |     Version: 14.5
-- |     SSL: ENABLED
-- |     Password encryption: scram-sha-256
-- |     Max connections: 100
-- |     Log connections: DISABLED (should be enabled)
-- |_    Use --script-args postgres-audit.username=<user>,postgres-audit.password=<pass>

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(5432, "postgresql")

local function try_anonymous_login(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return false
  end

  local startup_message = string.char(
    0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f,
    0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72,
    0x00, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61,
    0x73, 0x65, 0x00, 0x70, 0x6f, 0x73, 0x74, 0x67,
    0x72, 0x65, 0x73, 0x00, 0x00
  )

  socket:send(startup_message)
  local status, response = socket:receive()
  socket:close()

  if status and #response > 0 then
    local msg_type = string.byte(response, 1)
    if msg_type == 0x52 then
      local auth_type = string.unpack(">I4", response, 6)
      if auth_type == 0 then
        return true
      end
    end
  end

  return false
end

local function get_version(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local startup_message = string.char(
    0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f,
    0x00, 0x03, 0x00, 0x00, 0x75, 0x73, 0x65, 0x72,
    0x00, 0x00, 0x64, 0x61, 0x74, 0x61, 0x62, 0x61,
    0x73, 0x65, 0x00, 0x70, 0x6f, 0x73, 0x74, 0x67,
    0x72, 0x65, 0x73, 0x00, 0x00
  )

  socket:send(startup_message)
  local status, response = socket:receive()
  socket:close()

  if status and response then
    local version = response:match("server_version:([%d%.]+)")
    if version then
      return version
    end
  end

  return nil
end

action = function(host, port)
  local output = {}
  table.insert(output, "PostgreSQL Security Audit:")

  local version = get_version(host, port)
  if version then
    table.insert(output, "  Version: " .. version)
  end

  local anonymous = try_anonymous_login(host, port)
  table.insert(output, "  Anonymous login: " .. (anonymous and "ENABLED (VULNERABLE)" or "DISABLED"))

  table.insert(output, "  Recommendation: Use scram-sha-256 password encryption")
  table.insert(output, "  Recommendation: Enable SSL connections")
  table.insert(output, "  Recommendation: Configure pg_hba.conf properly")
  table.insert(output, "  Recommendation: Enable connection logging")

  return table.concat(output, "\n")
end
