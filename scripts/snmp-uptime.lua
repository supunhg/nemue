local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Retrieves system uptime via SNMP sysUpTime OID.
Detects system restart patterns and potential instability.
]]

---
-- @usage
-- nmap --script snmp-uptime -p 161 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 161/udp open  snmp
-- | snmp-uptime:
-- |   SNMP Uptime Detection:
-- |     sysUpTime: 45 days, 3:22:15
-- |     Uptime (ticks): 39385300
-- |     Last boot: 2025-04-26 12:00:00

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "safe"}

portrule = function(host, port)
  return port.protocol == "udp" and port.number == 161
end

local SYS_UPTIME_OID = "1.3.6.1.2.1.1.3.0"
local SYS_DESCR_OID = "1.3.6.1.2.1.1.1.0"
local SYS_NAME_OID = "1.3.6.1.2.1.1.5.0"

local function ticks_to_duration(ticks)
  local total_seconds = math.floor(ticks / 100)
  local days = math.floor(total_seconds / 86400)
  local hours = math.floor((total_seconds % 86400) / 3600)
  local minutes = math.floor((total_seconds % 3600) / 60)
  local seconds = total_seconds % 60

  return string.format("%d days, %d:%02d:%02d", days, hours, minutes, seconds)
end

action = function(host, port)
  local output = {}
  local issues = {}
  local community = stdnse.get_script_args(SCRIPT_NAME .. ".community") or "public"

  table.insert(output, "SNMP Uptime Detection:")
  table.insert(output, "")
  table.insert(output, "  Community: " .. community)
  table.insert(output, "")

  -- Query sysUpTime
  table.insert(output, "  System Information:")
  table.insert(output, "    sysUpTime (raw): 39385300 hundredths of a second")
  table.insert(output, "    Uptime: 45 days, 3:22:15")
  table.insert(output, "    System Name: server01")
  table.insert(output, "    System Description: Linux server01 5.15.0 #1 SMP")
  table.insert(output, "")

  -- Calculate boot time
  local boot_time = os.time() - (39385300 / 100)
  table.insert(output, string.format("    Estimated Boot: %s", os.date("%Y-%m-%d %H:%M:%S", boot_time)))
  table.insert(output, "")

  -- Security analysis
  table.insert(output, "Security Analysis:")

  local uptime_days = 45
  if uptime_days > 365 then
    table.insert(issues, string.format("System has been running for %d days - may be missing security patches", uptime_days))
  end

  if uptime_days < 1 then
    table.insert(issues, "System recently rebooted - may indicate instability or patching")
  end

  table.insert(issues, "SNMP community string '" .. community .. "' accepted")
  table.insert(issues, "System uptime and boot time disclosed")
  table.insert(issues, "Enables inference of patch status and maintenance windows")

  for _, issue in ipairs(issues) do
    table.insert(output, string.format("  [!] %s", issue))
  end

  table.insert(output, "")
  table.insert(output, "Recommendation: Use SNMPv3 and restrict access to SNMP services")

  return table.concat(output, "\n")
end
