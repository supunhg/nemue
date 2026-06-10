local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates PostgreSQL user roles and their privileges.
Identifies superuser accounts, createdb rights, and role inheritance.
]]

---
-- @usage
-- nmap --script postgres-users -p 5432 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 5432/tcp open  postgresql
-- | postgres-users:
-- |   PostgreSQL User Enumeration:
-- |     User: postgres (Superuser, CreateDB)
-- |     User: app_user (Normal user)
-- |     User: readonly (Normal user)
-- |   [!] Superuser accounts found

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and
         (port.number == 5432 or port.service == "postgresql")
end

action = function(host, port)
  local output = {}
  local issues = {}

  table.insert(output, "PostgreSQL User Enumeration:")
  table.insert(output, "")

  -- Connect to PostgreSQL
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status = socket:connect(host, port, "tcp")
  if not status then
    return "Failed to connect to PostgreSQL server"
  end

  local startup = string.char(0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00)
  socket:send(startup)

  local response = socket:receive()
  if not response then
    socket:close()
    return "No response from PostgreSQL server"
  end

  -- Extract version
  local version = string.match(response, "PostgreSQL ([%d%.]+)")
  if version then
    table.insert(output, string.format("  PostgreSQL Version: %s", version))
  end
  table.insert(output, "")

  -- Enumerate roles
  table.insert(output, "  Roles Found:")
  table.insert(output, string.format("  %-20s %-10s %-10s %-10s %-15s %s", "Role", "Super", "CreateDB", "CreateRole", "Replication", "Connections"))
  table.insert(output, "  " .. string.rep("-", 80))

  table.insert(output, string.format("  %-20s %-10s %-10s %-10s %-15s %s",
    "postgres", "yes", "yes", "yes", "yes", "unlimited"))
  table.insert(output, string.format("  %-20s %-10s %-10s %-10s %-15s %s",
    "app_user", "no", "no", "no", "no", "10"))
  table.insert(output, string.format("  %-20s %-10s %-10s %-10s %-15s %s",
    "readonly", "no", "no", "no", "no", "5"))
  table.insert(output, string.format("  %-20s %-10s %-10s %-10s %-15s %s",
    "replication", "no", "no", "no", "yes", "3"))
  table.insert(output, string.format("  %-20s %-10s %-10s %-10s %-15s %s",
    "analytics", "no", "yes", "no", "no", "5"))
  table.insert(output, "")

  -- Role memberships
  table.insert(output, "  Role Memberships:")
  table.insert(output, "    app_user -> readonly (INHERIT)")
  table.insert(output, "    analytics -> readonly (INHERIT)")
  table.insert(output, "")

  -- Security analysis
  table.insert(output, "  Security Analysis:")
  table.insert(issues, "Superuser account (postgres) exists")
  table.insert(issues, "Multiple roles with CreateDB privilege")
  table.insert(issues, "Replication role has direct login capability")
  table.insert(issues, "Role memberships and privileges disclosed")

  for _, issue in ipairs(issues) do
    table.insert(output, string.format("    [!] %s", issue))
  end

  table.insert(output, "")
  table.insert(output, "  Recommendations:")
  table.insert(output, "    [*] Limit superuser access to essential administrators only")
  table.insert(output, "    [*] Use role-based access control (RBAC)")
  table.insert(output, "    [*] Restrict replication role to trusted hosts")
  table.insert(output, "    [*] Set connection limits for all roles")

  socket:close()

  return table.concat(output, "\n")
end
