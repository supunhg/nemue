local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Queries NTP server for monitor list (monlist).
Detects NTP servers that respond to monlist requests which can be used for DDoS amplification.
]]

---
-- @usage
-- nmap --script ntp-ntpmon -p 123 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 123/udp open  ntp
-- | ntp-ntpmon:
-- |   NTP Monitor List:
-- |     Version: ntpd 4.2.8p15
-- |     Entries: 42
-- |   [!] Server responds to monlist (DDoS amplification risk)

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = function(host, port)
  return port.protocol == "udp" and port.number == 123
end

local NTP_MODE = 7
local NTP_MONLIST = 42

action = function(host, port)
  local output = {}
  local issues = {}

  -- Build NTP monlist request packet
  local packet = string.char(
    0x17,        -- LI=0, Version=3, Mode=7 (private)
    NTP_MONLIST, -- Request code: monlist
    0x00, 0x00,  -- Sequence number
    0x00, 0x00, 0x00, 0x00,  -- Status
    0x00, 0x00, 0x00, 0x00,  -- Association ID
    0x00, 0x00, 0x00, 0x00,  -- Offset
    0x00, 0x00, 0x00, 0x00   -- Count
  )

  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status = socket:connect(host, port, "udp")
  if not status then
    return "Failed to connect to NTP server"
  end

  socket:send(packet)
  local response = socket:receive()
  socket:close()

  if not response then
    return "No response from NTP server"
  end

  table.insert(output, "NTP Monitor List:")
  table.insert(output, "")

  local response_code = string.byte(response, 2)

  if response_code == 0x2a then  -- 42 = monlist response
    local num_items = 0
    if #response >= 4 then
      num_items = string.byte(response, 3) * 256 + string.byte(response, 4)
    end

    table.insert(output, string.format("  Response Code: monlist (%d)", response_code))
    table.insert(output, string.format("  Entries Returned: %d", num_items))
    table.insert(output, string.format("  Response Size: %d bytes", #response))

    table.insert(issues, "Server responds to NTP monlist requests")
    table.insert(issues, "Can be exploited for DDoS amplification attacks")
    table.insert(issues, "Amplification factor: ~556x")
  elseif response_code == 0x00 then
    table.insert(output, "  Server rejected monlist request (good)")
    table.insert(output, "  NTP mode 7 private requests disabled")
  else
    table.insert(output, string.format("  Response Code: %d", response_code))
    table.insert(output, "  Unexpected response - server may not be standard NTP")
  end

  if #issues > 0 then
    table.insert(output, "")
    table.insert(output, "Issues Found:")
    for _, issue in ipairs(issues) do
      table.insert(output, string.format("  [!] %s", issue))
    end
    table.insert(output, "")
    table.insert(output, "Recommendation: Disable NTP monlist or upgrade to ntpd 4.2.7p26+")
  end

  return table.concat(output, "\n")
end
