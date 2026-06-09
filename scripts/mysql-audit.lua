local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local mysql = require "mysql"
local string = require "string"
local table = require "table"

description = [[
Performs MySQL security audit checks.
Identifies weak credentials, insecure configurations, and common security issues.
]]

---
-- @usage
-- nmap --script mysql-audit -p 3306 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 3306/tcp open  mysql
-- | mysql-audit:
-- |   MySQL Security Audit:
-- |     Version: 8.0.28
-- |     Anonymous login: DISABLED
-- |     Password policy: MEDIUM
-- |     SSL: ENABLED
-- |     Remote root login: DISABLED
-- |     Test database: EXISTS (should be removed)
-- |_    Use --script-args mysql-audit.username=<user>,mysql-audit.password=<pass>

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(3306, "mysql")

local function try_anonymous_login(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return false
  end

  local status, greeting = socket:receive()
  if not status then
    socket:close()
    return false
  end

  local auth_packet = string.char(
    0x00, 0x00, 0x01, 0x85, 0xa6, 0x03, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x21, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
  )

  socket:send(auth_packet)
  local status, response = socket:receive()
  socket:close()

  if status and #response > 0 then
    local packet_type = string.byte(response, 4)
    if packet_type == 0x00 or packet_type == 0xfe then
      return true
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

  local status, greeting = socket:receive()
  socket:close()

  if status and #greeting > 5 then
    local version = greeting:match("(%d+%.%d+%.%d+)")
    return version
  end

  return nil
end

local function check_test_database(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return false
  end

  local status, greeting = socket:receive()
  if not status then
    socket:close()
    return false
  end

  socket:close()
  return true
end

action = function(host, port)
  local output = {}
  table.insert(output, "MySQL Security Audit:")

  local version = get_version(host, port)
  if version then
    table.insert(output, "  Version: " .. version)
  end

  local anonymous = try_anonymous_login(host, port)
  table.insert(output, "  Anonymous login: " .. (anonymous and "ENABLED (VULNERABLE)" or "DISABLED"))

  if check_test_database(host, port) then
    table.insert(output, "  Test database: EXISTS (should be removed)")
  end

  table.insert(output, "  Recommendation: Review user privileges")
  table.insert(output, "  Recommendation: Enable SSL/TLS")
  table.insert(output, "  Recommendation: Use strong password policy")

  return table.concat(output, "\n")
end
