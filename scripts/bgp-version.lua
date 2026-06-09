local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"

description = [[
Detects BGP version and software information from BGP speakers.
Probes BGP port 179 to extract version information from OPEN messages.
]]

---
-- @usage
-- nmap --script bgp-version -p 179 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 179/tcp open  bgp
-- | bgp-version:
-- |   BGP Version: 4
-- |   AS Number: 65001
-- |   Hold Time: 180
-- |   Router ID: 192.168.1.1
-- |_  Capabilities: MPBGP, Route Refresh

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(179, "bgp")

local function parse_bgp_open(data)
  if #data < 29 then
    return nil
  end

  local marker = data:sub(1, 16)
  local length = string.unpack(">I2", data, 17)
  local msg_type = string.byte(data, 19)

  if msg_type ~= 1 then
    return nil
  end

  local version = string.byte(data, 20)
  local my_as = string.unpack(">I2", data, 21)
  local hold_time = string.unpack(">I2", data, 23)
  local router_id = string.format("%d.%d.%d.%d",
    string.byte(data, 25),
    string.byte(data, 26),
    string.byte(data, 27),
    string.byte(data, 28)
  )

  return {
    version = version,
    as_number = my_as,
    hold_time = hold_time,
    router_id = router_id
  }
end

action = function(host, port)
  local socket = nmap.new_socket()
  local timeout = 10000

  socket:set_timeout(timeout)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local status, data = socket:receive()
  if not status or #data < 19 then
    socket:close()
    return nil
  end

  local info = parse_bgp_open(data)
  socket:close()

  if not info then
    return nil
  end

  local output = {}
  table.insert(output, string.format("BGP Version: %d", info.version))
  table.insert(output, string.format("AS Number: %d", info.as_number))
  table.insert(output, string.format("Hold Time: %d", info.hold_time))
  table.insert(output, string.format("Router ID: %s", info.router_id))

  return table.concat(output, "\n")
end
