local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local snmp = require "snmp"
local string = require "string"
local table = require "table"

description = [[
Brute forces SNMP community strings.
Tests common community strings against SNMP v1 and v2c services.
]]

---
-- @usage
-- nmap --script snmp-brute -p 161 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 161/udp open  snmp
-- | snmp-brute:
-- |   Valid community strings:
-- |     public - Read access
-- |     private - Read/Write access
-- |_    manager - Read access

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(161, "snmp")

local common_communities = {
  "public",
  "private",
  "community",
  "manager",
  "admin",
  "secret",
  "security",
  "snmp",
  "cisco",
  "all",
  "system",
  "read",
  "write",
  "agent",
  "mngt",
  "monitor",
  "default",
  "guest",
  "test",
  "user",
  "root",
  "switch",
  "router",
  "gateway",
  "access",
  "network",
  "server",
  "device",
  "password",
  "letmein"
}

local function test_community(host, port, community)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, port, "udp")
  if not status then
    return false
  end

  local oid = "1.3.6.1.2.1.1.1.0"
  local request = string.format(
    "\x30\x26\x02\x01\x01\x04%s%s\xa0\x18\x02\x04\x00\x00\x00\x00" ..
    "\x02\x01\x00\x02\x01\x00\x30\x0a\x30\x08\x06\x04%s\x05\x00",
    string.char(#community),
    community,
    oid
  )

  socket:send(request)

  local status, response = socket:receive()
  socket:close()

  if status and #response > 0 then
    local response_type = string.byte(response, 2)
    if response_type == #response - 2 then
      return true
    end
  end

  return false
end

local function check_write_access(host, port, community)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, port, "udp")
  if not status then
    return false
  end

  local oid = "1.3.6.1.2.1.1.6.0"
  local test_value = "nmap_test"

  local request = string.format(
    "\x30\x26\x02\x01\x01\x04%s%s\xa3\x18\x02\x04\x00\x00\x00\x00" ..
    "\x02\x01\x00\x02\x01\x00\x30\x0a\x30\x08\x06\x04%s\x04%s",
    string.char(#community),
    community,
    oid,
    test_value
  )

  socket:send(request)

  local status, response = socket:receive()
  socket:close()

  if status and #response > 0 then
    local error_status = string.byte(response, 16)
    return error_status == 0
  end

  return false
end

action = function(host, port)
  local output = {}
  local found = 0

  for _, community in ipairs(common_communities) do
    if test_community(host, port, community) then
      found = found + 1
      local access_level = "Read access"

      if check_write_access(host, port, community) then
        access_level = "Read/Write access"
      end

      table.insert(output, string.format("%s - %s", community, access_level))
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Valid community strings found:")
    for _, line in ipairs(output) do
      table.insert(result, "  " .. line)
    end
    table.insert(result, string.format("\nTotal found: %d", found))
    return table.concat(result, "\n")
  end

  return "No valid community strings found"
end
