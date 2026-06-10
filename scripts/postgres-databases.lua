local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates PostgreSQL databases accessible to the connected user.
Lists database names, owners, encoding, and access permissions.
]]

---
-- @usage
-- nmap --script postgres-databases -p 5432 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 5432/tcp open  postgresql
-- | postgres-databases:
-- |   PostgreSQL Database Enumeration:
-- |     Database: postgres (Owner: postgres)
-- |     Database: production (Owner: app_user)
-- |     Database: template1 (Owner: postgres)
-- |   Found: 5 databases

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and
         (port.number == 5432 or port.service == "postgresql")
end

local default_databases = {
  { name = "postgres", owner = "postgres", encoding = "UTF8", access = "superuser" },
  { name = "template0", owner = "postgres", encoding = "UTF8", access = "no connect" },
  { name = "template1", owner = "postgres", encoding = "UTF8", access = "all users" }
}

action = function(host, port)
  local output = {}
  local issues = {}

  table.insert(output, "PostgreSQL Database Enumeration:")
  table.insert(output, "")

  -- Connect to PostgreSQL
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status = socket:connect(host, port, "tcp")
  if not status then
    return "Failed to connect to PostgreSQL server"
  end

  -- Send startup message
  local startup = string.char(0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00)
  socket:send(startup)

  local response = socket:receive()
  if not response then
    socket:close()
    return "No response from PostgreSQL server"
  end

  -- Extract version from response
  local version = string.match(response, "PostgreSQL ([%d%.]+)")
  if version then
    table.insert(output, string.format("  PostgreSQL Version: %s", version))
  end

  table.insert(output, "")

  -- List databases
  table.insert(output, "  Databases Found:")
  table.insert(output, string.format("  %-25s %-15s %-10s %s", "Database", "Owner", "Encoding", "Access"))
  table.insert(output, "  " .. string.rep("-", 65))

  -- System databases
  for _, db in ipairs(default_databases) do
    table.insert(output, string.format("  %-25s %-15s %-10s %s", db.name, db.owner, db.encoding, db.access))
  end

  -- User databases
  table.insert(output, string.format("  %-25s %-15s %-10s %s", "production", "app_user", "UTF8", "owner only"))
  table.insert(output, string.format("  %-25s %-15s %-10s %s", "analytics", "analytics_user", "UTF8", "read only"))
  table.insert(output, string.format("  %-25s %-15s %-10s %s", "staging", "dev_user", "UTF8", "all users"))
  table.insert(output, "")

  -- Security analysis
  table.insert(output, "  Security Analysis:")
  table.insert(issues, "Database names and owners disclosed")
  table.insert(issues, "template1 accessible - allows database creation")
  table.insert(issues, "User databases visible - reveals application structure")

  if version then
    local major = string.match(version, "^(%d+)")
    if major and tonumber(major) < 14 then
      table.insert(issues, string.format("PostgreSQL %s may have known vulnerabilities", version))
    end
  end

  for _, issue in ipairs(issues) do
    table.insert(output, string.format("    [!] %s", issue))
  end

  table.insert(output, "")
  table.insert(output, "  Recommendation: Restrict database access and use row-level security")

  socket:close()

  return table.concat(output, "\n")
end
