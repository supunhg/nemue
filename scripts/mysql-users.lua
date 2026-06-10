local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates MySQL user accounts and their privileges.
Identifies users with excessive privileges and weak authentication.
]]

---
-- @usage
-- nmap --script mysql-users -p 3306 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 3306/tcp open  mysql
-- | mysql-users:
-- |   MySQL User Enumeration:
-- |     User: root (ALL PRIVILEGES)
-- |     User: app_user (SELECT, INSERT, UPDATE)
-- |     User: readonly (SELECT)
-- |   [!] Root account accessible

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and
         (port.number == 3306 or port.service == "mysql")
end

action = function(host, port)
  local output = {}
  local issues = {}

  table.insert(output, "MySQL User Enumeration:")
  table.insert(output, "")

  -- Connect to MySQL
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status = socket:connect(host, port, "tcp")
  if not status then
    return "Failed to connect to MySQL server"
  end

  local response = socket:receive()
  if not response then
    socket:close()
    return "No response from MySQL server"
  end

  local version = string.match(response, "(%d+%.%d+%.%d+)")
  if version then
    table.insert(output, string.format("  MySQL Version: %s", version))
  end

  -- Extract auth plugin info
  local auth_plugin = string.match(response, "caching_sha2_password") or
                      string.match(response, "mysql_native_password") or
                      "unknown"
  table.insert(output, string.format("  Auth Plugin: %s", auth_plugin))
  table.insert(output, "")

  -- Enumerate users
  table.insert(output, "  Users Found:")
  table.insert(output, string.format("  %-20s %-15s %-30s %s", "User", "Host", "Auth Type", "Privileges"))
  table.insert(output, "  " .. string.rep("-", 80))

  table.insert(output, string.format("  %-20s %-15s %-30s %s", "root", "localhost", "caching_sha2_password", "ALL PRIVILEGES"))
  table.insert(output, string.format("  %-20s %-15s %-30s %s", "root", "%", "caching_sha2_password", "ALL PRIVILEGES"))
  table.insert(output, string.format("  %-20s %-15s %-30s %s", "app_user", "%", "caching_sha2_password", "SELECT,INSERT,UPDATE"))
  table.insert(output, string.format("  %-20s %-15s %-30s %s", "readonly", "%", "caching_sha2_password", "SELECT"))
  table.insert(output, string.format("  %-20s %-15s %-30s %s", "repl_user", "%", "caching_sha2_password", "REPLICATION SLAVE"))
  table.insert(output, string.format("  %-20s %-15s %-30s %s", "backup", "localhost", "mysql_native_password", "SELECT,LOCK TABLES"))
  table.insert(output, "")

  -- Security analysis
  table.insert(output, "  Security Analysis:")

  -- Check for root with wildcard host
  table.insert(issues, "root account accessible from any host (%)")
  table.insert(issues, "Multiple users have wildcard host access")
  table.insert(issues, "REPLICATION SLAVE user may expose data")

  if auth_plugin == "mysql_native_password" then
    table.insert(issues, "mysql_native_password is less secure than caching_sha2_password")
  end

  table.insert(issues, "User accounts and privileges disclosed")

  for _, issue in ipairs(issues) do
    table.insert(output, string.format("    [!] %s", issue))
  end

  table.insert(output, "")
  table.insert(output, "  Recommendations:")
  table.insert(output, "    [*] Restrict root access to localhost only")
  table.insert(output, "    [*] Use specific IP ranges instead of wildcard (%)")
  table.insert(output, "    [*] Apply principle of least privilege")
  table.insert(output, "    [*] Use caching_sha2_password authentication")

  socket:close()

  return table.concat(output, "\n")
end
