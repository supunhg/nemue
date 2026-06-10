local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates Redis databases and their contents.
Lists database sizes, key counts, and memory usage.
]]

---
-- @usage
-- nmap --script redis-databases -p 6379 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 6379/tcp open  redis
-- | redis-databases:
-- |   Redis Database Enumeration:
-- |     db0: keys=1234, expires=56
-- |     db1: keys=89, expires=12
-- |     db2: keys=0, expires=0
-- |   Total keys: 1323

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe", "database"}

portrule = function(host, port)
  return port.protocol == "tcp" and
         (port.number == 6379 or port.service == "redis")
end

local function send_redis_command(socket, command)
  local parts = {}
  for word in string.gmatch(command, "%S+") do
    table.insert(parts, word)
  end

  local cmd = string.format("*%d\r\n", #parts)
  for _, part in ipairs(parts) do
    cmd = cmd .. string.format("$%d\r\n%s\r\n", #part, part)
  end

  socket:send(cmd)
  return socket:receive()
end

action = function(host, port)
  local output = {}
  local issues = {}
  local total_keys = 0

  table.insert(output, "Redis Database Enumeration:")
  table.insert(output, "")

  -- Connect to Redis
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status = socket:connect(host, port, "tcp")
  if not status then
    return "Failed to connect to Redis server"
  end

  -- Get server info
  local info_response = send_redis_command(socket, "INFO server")
  if info_response then
    local version = string.match(info_response, "redis_version:([%d%.]+)")
    local mode = string.match(info_response, "redis_mode:(%w+)")
    local os_info = string.match(info_response, "os:([^\r\n]+)")

    if version then
      table.insert(output, string.format("  Redis Version: %s", version))
    end
    if mode then
      table.insert(output, string.format("  Mode: %s", mode))
    end
    if os_info then
      table.insert(output, string.format("  OS: %s", os_info))
    end
    table.insert(output, "")
  end

  -- Check authentication
  local ping_response = send_redis_command(socket, "PING")
  if ping_response and string.find(ping_response, "NOAUTH") then
    table.insert(output, "  Authentication: required")
  elseif ping_response and string.find(ping_response, "PONG") then
    table.insert(output, "  Authentication: not required")
    table.insert(issues, "Redis accessible without authentication")
  end
  table.insert(output, "")

  -- Get database info
  local dbinfo_response = send_redis_command(socket, "INFO keyspace")
  if dbinfo_response then
    table.insert(output, "  Databases:")
    table.insert(output, string.format("  %-10s %-15s %-15s", "Database", "Keys", "Expires"))
    table.insert(output, "  " .. string.rep("-", 40))

    for db, keys, expires in string.gmatch(dbinfo_response, "(db%d+):keys=(%d+),expires=(%d+)") do
      table.insert(output, string.format("  %-10s %-15s %-15s", db, keys, expires))
      total_keys = total_keys + tonumber(keys)
    end

    -- List common databases even if empty
    for i = 0, 15 do
      local db_name = "db" .. i
      if not string.find(dbinfo_response, db_name) then
        table.insert(output, string.format("  %-10s %-15s %-15s", db_name, "0", "0"))
      end
    end

    table.insert(output, "")
    table.insert(output, string.format("  Total Keys: %d", total_keys))
  end

  -- Get memory info
  local mem_response = send_redis_command(socket, "INFO memory")
  if mem_response then
    local used_memory = string.match(mem_response, "used_memory_human:([^\r\n]+)")
    local max_memory = string.match(mem_response, "maxmemory_human:([^\r\n]+)")

    if used_memory then
      table.insert(output, "")
      table.insert(output, "  Memory Usage:")
      table.insert(output, string.format("    Used: %s", used_memory))
      table.insert(output, string.format("    Max: %s", max_memory or "unlimited"))
    end
  end

  table.insert(output, "")

  -- Security analysis
  table.insert(output, "  Security Analysis:")
  table.insert(issues, "Database contents and sizes disclosed")
  table.insert(issues, "Key enumeration possible via KEYS command")
  table.insert(issues, "Memory usage information exposed")

  if total_keys > 0 then
    table.insert(issues, string.format("Database contains %d keys - verify sensitive data protection", total_keys))
  end

  for _, issue in ipairs(issues) do
    table.insert(output, string.format("    [!] %s", issue))
  end

  table.insert(output, "")
  table.insert(output, "  Recommendations:")
  table.insert(output, "    [*] Require authentication (requirepass)")
  table.insert(output, "    [*] Bind to specific interfaces")
  table.insert(output, "    [*] Disable dangerous commands (KEYS, FLUSHALL, CONFIG)")
  table.insert(output, "    [*] Use ACLs for fine-grained access control")

  socket:close()

  return table.concat(output, "\n")
end
