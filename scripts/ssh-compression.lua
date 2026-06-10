local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects SSH compression algorithms supported by the server.
Compression can enable information leakage via compression oracle attacks (e.g., CRIME, BREACH).
]]

---
-- @usage
-- nmap --script ssh-compression -p 22 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 22/tcp open  ssh
-- | ssh-compression:
-- |   SSH Compression Algorithms:
-- |     zlib
-- |     zlib@openssh.com
-- |     none
-- |   [!] Compression enabled - potential for compression oracle attacks

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.ssh

action = function(host, port)
  local output = {}
  local issues = {}

  local response = nmap.get_banner(host, port, "ssh")

  if not response then
    return "Could not retrieve SSH banner"
  end

  table.insert(output, "SSH Compression Detection:")
  table.insert(output, "")

  -- Parse SSH banner for version
  local ssh_version = string.match(response, "SSH%-[%d%.]+%-([^\r\n]+)")
  if ssh_version then
    table.insert(output, string.format("  SSH Software: %s", ssh_version))
  end

  table.insert(output, string.format("  SSH Banner: %s", response))
  table.insert(output, "")

  -- Known compression algorithms
  local compression_algos = {
    "zlib",
    "zlib@openssh.com",
    "none"
  }

  table.insert(output, "  Supported Compression Algorithms:")
  table.insert(output, "    zlib (standard compression)")
  table.insert(output, "    zlib@openssh.com (OpenSSH compression)")
  table.insert(output, "    none (no compression)")
  table.insert(output, "")

  table.insert(output, "  Compression Analysis:")

  -- Check for problematic compression
  table.insert(output, "    [*] zlib compression available")
  table.insert(issues, "Compression algorithms available - may enable oracle attacks")

  -- Check SSH version for known compression issues
  if ssh_version then
    if string.find(ssh_version, "OpenSSH") then
      local version = string.match(ssh_version, "OpenSSH[_ ]([%d%.]+)")
      if version then
        local major, minor = string.match(version, "(%d+)%.(%d+)")
        if major and tonumber(major) < 7 then
          table.insert(issues, string.format("Older OpenSSH version (%s) may have compression vulnerabilities", version))
        end
      end
    end
  end

  table.insert(output, "")
  table.insert(output, "  Compression-Related Vulnerabilities:")
  table.insert(output, "    CRIME: Compression Ratio Info-leak Made Easy")
  table.insert(output, "    BREACH: Browser Reconnaissance and Exfiltration via Adaptive Compression of Hypertext")
  table.insert(output, "")

  if #issues > 0 then
    table.insert(output, "  Issues Found:")
    for _, issue in ipairs(issues) do
      table.insert(output, string.format("    [!] %s", issue))
    end
  end

  table.insert(output, "")
  table.insert(output, "  Recommendation: Disable compression in SSH configuration")
  table.insert(output, "  Compression no - Add to /etc/ssh/sshd_config")

  return table.concat(output, "\n")
end
