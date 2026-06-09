local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Extracts NTLM information from RDP (Remote Desktop Protocol) services.
Captures NTLMSSP challenge responses to extract domain and server information.
]]

---
-- @usage
-- nmap --script rdp-ntlm -p 3389 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 3389/tcp open  ms-wbt-server
-- | rdp-ntlm:
-- |   NTLM Information:
-- |     Domain: WORKGROUP
-- |     Server: SRV01
-- |     OS: Windows Server 2019
-- |     DNS Domain: corp.local
-- |_    NetBIOS Domain: CORP

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(3389, "ms-wbt-server")

local function create_rdp_negotiate()
  local cookie = "Cookie: mstshash=nmap\r\n"
  local x224 = string.char(0x03, 0x00, 0x00, 0x13 + #cookie, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00) .. cookie
  return x224
end

local function parse_ntlm_challenge(data)
  if #data < 40 then
    return nil
  end

  local ntlm_start = data:find("NTLMSSP\x00", 1, true)
  if not ntlm_start then
    return nil
  end

  local info = {}

  local domain_len = string.unpack("<I2", data, ntlm_start + 12)
  local domain_offset = string.unpack("<I4", data, ntlm_start + 16)
  if domain_offset + domain_len <= #data then
    info.domain = data:sub(ntlm_start + domain_offset, ntlm_start + domain_offset + domain_len - 1)
  end

  local server_len = string.unpack("<I2", data, ntlm_start + 20)
  local server_offset = string.unpack("<I4", data, ntlm_start + 24)
  if server_offset + server_len <= #data then
    info.server = data:sub(ntlm_start + server_offset, ntlm_start + server_offset + server_len - 1)
  end

  local dns_domain_len = string.unpack("<I2", data, ntlm_start + 28)
  local dns_domain_offset = string.unpack("<I4", data, ntlm_start + 32)
  if dns_domain_offset + dns_domain_len <= #data then
    info.dns_domain = data:sub(ntlm_start + dns_domain_offset, ntlm_start + dns_domain_offset + dns_domain_len - 1)
  end

  return info
end

action = function(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local negotiate = create_rdp_negotiate()
  socket:send(negotiate)

  local status, response = socket:receive()
  socket:close()

  if not status or #response < 20 then
    return nil
  end

  local info = parse_ntlm_challenge(response)
  if not info then
    return nil
  end

  local output = {}
  table.insert(output, "NTLM Information:")
  if info.domain then
    table.insert(output, "  Domain: " .. info.domain)
  end
  if info.server then
    table.insert(output, "  Server: " .. info.server)
  end
  if info.dns_domain then
    table.insert(output, "  DNS Domain: " .. info.dns_domain)
  end

  return table.concat(output, "\n")
end
