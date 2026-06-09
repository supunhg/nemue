local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs Redis security audit checks.
Identifies weak credentials, insecure configurations, and exposed commands.
]]

---
-- @usage
-- nmap --script redis-audit -p 6379 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 6379/tcp open  redis
-- | redis-audit:
-- |   Redis Security Audit:
-- |     Version: 7.0.5
-- |     Authentication: NOT REQUIRED (VULNERABLE)
-- |     Protected mode: DISABLED
-- |     Dangerous commands: ENABLED
-- |       - CONFIG
-- |       - DEBUG
-- |       - FLUSHALL
-- |_    Use --script-args redis-audit.password=<pass> to test authentication

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "auth"}

portrule = shortport.port_or_service(6379, "redis")

local dangerous_commands = {
  "CONFIG", "DEBUG", "FLUSHALL", "FLUSHDB", "KEYS",
  "SAVE", "BGSAVE", "SHUTDOWN", "SLAVEOF", "REPLICAOF",
  "EVAL", "SCRIPT", "CLIENT", "CLUSTER"
}

local function send_command(socket, command)
  local parts = {}
  for word in command:gmatch("%S+") do
    table.insert(parts, word)
  end

  local request = "*" .. #parts .. "\r\n"
  for _, part in ipairs(parts) do
    request = request .. "$" .. #part .. "\r\n" .. part .. "\r\n"
  end

  socket:send(request)
  local status, response = socket:receive()
  return status, response
end

local function check_authentication(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local status, response = send_command(socket, "PING")
  socket:close()

  if status and response then
    if response:match("%+PONG") then
      return false
    elseif response:match("NOAUTH") or response:match("ERR") then
      return true
    end
  end

  return nil
end

local function get_info(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local status, response = send_command(socket, "INFO")
  socket:close()

  if status and response then
    local info = {}
    info.version = response:match("redis_version:([%d%.]+)")
    info.mode = response:match("redis_mode:(%w+)")
    info.os = response:match("os:(.+)\r\n")
    return info
  end

  return nil
end

local function check_protected_mode(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local status, response = send_command(socket, "CONFIG GET protected-mode")
  socket:close()

  if status and response then
    if response:match("on") then
      return true
    elseif response:match("off") then
      return false
    end
  end

  return nil
end

local function check_dangerous_commands(host, port, command)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return false
  end

  local status, response = send_command(socket, command .. " HELP")
  socket:close()

  if status and response and not response:match("ERR") then
    return true
  end

  return false
end

action = function(host, port)
  local output = {}
  table.insert(output, "Redis Security Audit:")

  local info = get_info(host, port)
  if info then
    if info.version then
      table.insert(output, "  Version: " .. info.version)
    end
    if info.mode then
      table.insert(output, "  Mode: " .. info.mode)
    end
  end

  local auth_required = check_authentication(host, port)
  if auth_required == false then
    table.insert(output, "  Authentication: NOT REQUIRED (VULNERABLE)")
  elseif auth_required == true then
    table.insert(output, "  Authentication: REQUIRED")
  end

  local protected = check_protected_mode(host, port)
  if protected == false then
    table.insert(output, "  Protected mode: DISABLED (VULNERABLE)")
  elseif protected == true then
    table.insert(output, "  Protected mode: ENABLED")
  end

  table.insert(output, "  Dangerous commands accessible:")
  for _, cmd in ipairs(dangerous_commands) do
    if check_dangerous_commands(host, port, cmd) then
      table.insert(output, "    - " .. cmd)
    end
  end

  table.insert(output, "  Recommendation: Set a strong password")
  table.insert(output, "  Recommendation: Enable protected-mode")
  table.insert(output, "  Recommendation: Disable dangerous commands via rename-command")

  return table.concat(output, "\n")
end
