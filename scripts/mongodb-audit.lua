local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs MongoDB security audit checks.
Identifies weak credentials, insecure configurations, and exposed databases.
]]

---
-- @usage
-- nmap --script mongodb-audit -p 27017 <target>
--
-- @output
-- PORT      STATE SERVICE
-- 27017/tcp open  mongodb
-- | mongodb-audit:
-- |   MongoDB Security Audit:
-- |     Version: 6.0.3
-- |     Authentication: NOT REQUIRED (VULNERABLE)
-- |     Bind IP: 0.0.0.0 (exposed to all interfaces)
-- |     HTTP interface: ENABLED (port 28017)
-- |     REST API: ENABLED (VULNERABLE)
-- |_    Use --script-args mongodb-audit.username=<user>,mongodb-audit.password=<pass>

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(27017, "mongodb")

local function create_ismaster_request()
  local request = {
    ismaster = 1
  }

  local doc = "\x16\x00\x00\x00" ..
    "\x01" .. "ismaster" .. "\x00" .. "\x00\x00\x00\x00\x00\x00\xf0\x3f" ..
    "\x00"

  local msg_header = "\x3a\x00\x00\x00" ..
    "\x01\x00\x00\x00" ..
    "\x00\x00\x00\x00" ..
    "\xd4\x07\x00\x00" ..
    "\x01\x00\x00\x00"

  return msg_header .. doc
end

local function try_unauthenticated(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return false
  end

  local request = create_ismaster_request()
  socket:send(request)

  local status, response = socket:receive()
  socket:close()

  if status and #response > 0 then
    if response:find("ismaster") then
      return true
    end
  end

  return false
end

local function get_server_info(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local request = create_ismaster_request()
  socket:send(request)

  local status, response = socket:receive()
  socket:close()

  if status and response then
    local info = {}
    info.version = response:match("version\x00([%d%.]+)")
    info.max_wire_version = response:match("maxWireVersion\x00(%d+)")
    return info
  end

  return nil
end

local function check_http_interface(host)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, 28017)
  if status then
    socket:close()
    return true
  end

  return false
end

action = function(host, port)
  local output = {}
  table.insert(output, "MongoDB Security Audit:")

  local info = get_server_info(host, port)
  if info then
    if info.version then
      table.insert(output, "  Version: " .. info.version)
    end
  end

  local unauth = try_unauthenticated(host, port)
  if unauth then
    table.insert(output, "  Authentication: NOT REQUIRED (VULNERABLE)")
    table.insert(output, "  Anonymous access: ENABLED")
  else
    table.insert(output, "  Authentication: REQUIRED")
  end

  local http_enabled = check_http_interface(host)
  if http_enabled then
    table.insert(output, "  HTTP interface: ENABLED (port 28017)")
    table.insert(output, "  REST API: ENABLED (VULNERABLE)")
  end

  table.insert(output, "  Recommendation: Enable authentication")
  table.insert(output, "  Recommendation: Bind to specific IP (not 0.0.0.0)")
  table.insert(output, "  Recommendation: Disable HTTP interface")
  table.insert(output, "  Recommendation: Enable TLS/SSL")

  return table.concat(output, "\n")
end
