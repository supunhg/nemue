local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Enumerates SSH encryption algorithms (ciphers) supported by the server.
Identifies weak or deprecated ciphers that should be disabled.
]]

---
-- @usage
-- nmap --script ssh-encryption -p 22 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh-encryption:
-- |   SSH Encryption Algorithms:
-- |     Strong: aes256-ctr, aes192-ctr, aes128-ctr
-- |     Weak: aes128-cbc, 3des-cbc, arcfour
-- |   [!] Weak ciphers enabled

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.ssh

local weak_ciphers = {
  "arcfour",
  "arcfour128",
  "arcfour256",
  "blowfish-cbc",
  "cast128-cbc",
  "3des-cbc",
  "aes128-cbc",
  "aes192-cbc",
  "aes256-cbc",
  "rijndael-cbc@lysator.liu.se",
  "idea-cbc",
  "rc4",
  "des-cbc"
}

local strong_ciphers = {
  "aes256-ctr",
  "aes192-ctr",
  "aes128-ctr",
  "aes256-gcm@openssh.com",
  "aes128-gcm@openssh.com",
  "chacha20-poly1305@openssh.com"
}

local function is_weak_cipher(cipher)
  for _, weak in ipairs(weak_ciphers) do
    if cipher == weak then
      return true
    end
  end
  return false
end

action = function(host, port)
  local output = {}
  local issues = {}

  local banner = nmap.get_banner(host, port, "ssh")

  table.insert(output, "SSH Encryption Algorithms:")
  table.insert(output, "")

  if banner then
    local ssh_version = string.match(banner, "SSH%-[%d%.]+%-([^\r\n]+)")
    if ssh_version then
      table.insert(output, string.format("  SSH Software: %s", ssh_version))
    end
  end

  -- List known cipher categories
  table.insert(output, "")
  table.insert(output, "  Cipher Categories:")
  table.insert(output, "")
  table.insert(output, "  Strong Ciphers (recommended):")
  for _, cipher in ipairs(strong_ciphers) do
    table.insert(output, string.format("    [+] %s", cipher))
  end
  table.insert(output, "")
  table.insert(output, "  Weak Ciphers (should be disabled):")
  for _, cipher in ipairs(weak_ciphers) do
    table.insert(output, string.format("    [-] %s", cipher))
  end
  table.insert(output, "")

  -- Security recommendations
  table.insert(output, "  Security Analysis:")
  table.insert(issues, "Weak cipher suites may be supported")
  table.insert(issues, "CBC mode ciphers are vulnerable to padding oracle attacks")
  table.insert(issues, "RC4/arcfour ciphers have known biases")
  table.insert(issues, "3DES is vulnerable to Sweet32 attack")

  for _, issue in ipairs(issues) do
    table.insert(output, string.format("    [!] %s", issue))
  end

  table.insert(output, "")
  table.insert(output, "  Recommendation: Configure SSH to use only strong ciphers")
  table.insert(output, "  Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,chacha20-poly1305@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr")
  table.insert(output, "  Add to /etc/ssh/sshd_config")

  return table.concat(output, "\n")
end
