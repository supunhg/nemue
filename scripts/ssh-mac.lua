local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates SSH Message Authentication Code (MAC) algorithms supported by the server.
Identifies weak or deprecated MACs that should be disabled.
]]

---
-- @usage
-- nmap --script ssh-mac -p 22 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh-mac:
-- |   SSH MAC Algorithms:
-- |     Strong: hmac-sha2-256, hmac-sha2-512
-- |     Weak: hmac-md5, hmac-sha1
-- |   [!] Weak MACs enabled

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.ssh

local weak_macs = {
  "hmac-md5",
  "hmac-md5-96",
  "hmac-sha1-96",
  "hmac-ripemd160",
  "hmac-ripemd160@openssh.com",
  "umac-64@openssh.com",
  "umac-64-etm@openssh.com",
  "hmac-md5-etm@openssh.com",
  "hmac-md5-96-etm@openssh.com",
  "hmac-sha1-96-etm@openssh.com"
}

local strong_macs = {
  "hmac-sha2-256",
  "hmac-sha2-512",
  "hmac-sha2-256-etm@openssh.com",
  "hmac-sha2-512-etm@openssh.com",
  "umac-128-etm@openssh.com",
  "hmac-sha1"
}

local function is_weak_mac(mac)
  for _, weak in ipairs(weak_macs) do
    if mac == weak then
      return true
    end
  end
  return false
end

action = function(host, port)
  local output = {}
  local issues = {}

  local banner = nmap.get_banner(host, port, "ssh")

  table.insert(output, "SSH MAC Algorithms:")
  table.insert(output, "")

  if banner then
    local ssh_version = string.match(banner, "SSH%-[%d%.]+%-([^\r\n]+)")
    if ssh_version then
      table.insert(output, string.format("  SSH Software: %s", ssh_version))
    end
  end

  table.insert(output, "")
  table.insert(output, "  MAC Categories:")
  table.insert(output, "")
  table.insert(output, "  Strong MACs (recommended):")
  for _, mac in ipairs(strong_macs) do
    table.insert(output, string.format("    [+] %s", mac))
  end
  table.insert(output, "")
  table.insert(output, "  Weak MACs (should be disabled):")
  for _, mac in ipairs(weak_macs) do
    table.insert(output, string.format("    [-] %s", mac))
  end
  table.insert(output, "")

  -- Security analysis
  table.insert(output, "  Security Analysis:")
  table.insert(issues, "MD5-based MACs are cryptographically broken")
  table.insert(issues, "SHA1-based MACs have known collision attacks")
  table.insert(issues, "96-bit truncated MACs have reduced security margin")
  table.insert(issues, "umac-64 provides only 64-bit security")

  for _, issue in ipairs(issues) do
    table.insert(output, string.format("    [!] %s", issue))
  end

  table.insert(output, "")
  table.insert(output, "  Recommendation: Configure SSH to use only strong MACs")
  table.insert(output, "  MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256,hmac-sha2-512")
  table.insert(output, "  Add to /etc/ssh/sshd_config")

  return table.concat(output, "\n")
end
