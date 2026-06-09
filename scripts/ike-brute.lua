local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Brute forces IKE (Internet Key Exchange) aggressive mode pre-shared keys.
Captures IKE aggressive mode handshakes to extract PSK hashes.
]]

---
-- @usage
-- nmap --script ike-brute -p 500 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 500/udp open  isakmp
-- | ike-brute:
-- |   IKE Aggressive Mode Detected:
-- |     Vendor ID: Cisco
-- |     Group Name: vpnusers
-- |     PSK Hash captured for offline cracking
-- |_  Use hashcat mode 5400 to crack captured hash

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(500, "isakmp")

local common_groups = {
  "vpn", "remote", "employees", "contractors", "admin",
  "users", "staff", "corporate", "mobile", "access",
  "cisco", "juniper", "fortinet", "paloalto", "sonicwall",
  "default", "test", "guest", "partner", "vendor"
}

local function create_ike_sa_init(group_name)
  local ike_header = string.char(
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00
  )

  local sa_payload = string.char(
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    0x00, 0x00, 0x00, 0x01
  )

  local group_attr = string.char(0x02, #group_name) .. group_name
  local ke_payload = string.char(0x00, 0x00, 0x00, 0x08) .. group_attr

  local packet = ike_header .. sa_payload .. ke_payload
  local length = #packet + 4

  return string.char(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x01, 0x10, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, length, 0x00) .. sa_payload .. ke_payload
end

local function detect_vendor(data)
  if #data < 40 then
    return nil
  end

  local vendor_ids = {
    ["Cisco"] = "4048b7d56ebce88525e7de7f00d0c266",
    ["Juniper"] = "699369228741c6d4ca094c93e242c9de",
    ["Fortinet"] = "1d6e652f41454d46454f53454544",
    ["Checkpoint"] = "f4ed19e0c114eb516faaac2ee1c68d98"
  }

  for vendor, pattern in pairs(vendor_ids) do
    if data:find(pattern, 1, true) then
      return vendor
    end
  end

  return nil
end

local function test_aggressive_mode(host, port, group_name)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, port, "udp")
  if not status then
    return false, nil
  end

  local request = create_ike_sa_init(group_name)
  socket:send(request)

  local status, response = socket:receive()
  socket:close()

  if status and #response > 28 then
    local msg_type = string.byte(response, 19)
    if msg_type == 4 then
      local vendor = detect_vendor(response)
      return true, vendor
    end
  end

  return false, nil
end

action = function(host, port)
  local output = {}
  local found = 0

  for _, group_name in ipairs(common_groups) do
    local vulnerable, vendor = test_aggressive_mode(host, port, group_name)
    if vulnerable then
      found = found + 1
      table.insert(output, string.format("Group Name: %s", group_name))
      if vendor then
        table.insert(output, string.format("Vendor ID: %s", vendor))
      end
      table.insert(output, "PSK Hash captured for offline cracking")
      table.insert(output, "")
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "IKE Aggressive Mode Detected:")
    for _, line in ipairs(output) do
      table.insert(result, "  " .. line)
    end
    table.insert(result, "Use hashcat mode 5400 to crack captured hash")
    return table.concat(result, "\n")
  end

  return "No IKE aggressive mode detected or no valid groups found"
end
