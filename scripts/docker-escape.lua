local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects potential Docker escape vulnerabilities and misconfigurations.
Checks for exposed Docker sockets and common container escape vectors.
]]

---
-- @usage
-- nmap --script docker-escape -p 2375,2376 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 2375/tcp open  docker
-- | docker-escape:
-- |   Docker Escape Risks:
-- |     Docker API exposed without authentication
-- |     Privileged containers detected
-- |     Sensitive mounts found:
-- |       - /var/run/docker.sock
-- |       - /proc/sysrq-trigger
-- |     Capabilities: SYS_ADMIN, NET_ADMIN
-- |_    Recommendation: Restrict Docker API access

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(2375, "docker")

local sensitive_mounts = {
  "/var/run/docker.sock",
  "/proc/sysrq-trigger",
  "/proc/sys",
  "/proc/1",
  "/sys/kernel",
  "/dev",
  "/etc/shadow",
  "/etc/passwd",
  "/root",
  "/host"
}

local dangerous_capabilities = {
  "SYS_ADMIN",
  "NET_ADMIN",
  "SYS_PTRACE",
  "SYS_RAWIO",
  "SYS_MODULE",
  "DAC_READ_SEARCH",
  "NET_RAW",
  "SYS_CHROOT"
}

local function check_api_exposure(host, port)
  local response = http.get(host, port, "/version")
  if response and response.status == 200 then
    return true, response.body
  end
  return false, nil
end

local function list_containers(host, port)
  local response = http.get(host, port, "/containers/json")
  if response and response.status == 200 then
    return true, response.body
  end
  return false, nil
end

local function check_privileged(container_info)
  if container_info:match('"Privileged":true') then
    return true
  end
  return false
end

local function check_mounts(container_info)
  local found_mounts = {}
  for _, mount in ipairs(sensitive_mounts) do
    if container_info:match(mount:gsub("/", "\\/")) then
      table.insert(found_mounts, mount)
    end
  end
  return found_mounts
end

local function check_capabilities(container_info)
  local found_caps = {}
  for _, cap in ipairs(dangerous_capabilities) do
    if container_info:match(cap) then
      table.insert(found_caps, cap)
    end
  end
  return found_caps
end

action = function(host, port)
  local output = {}
  local vuln_count = 0

  local api_exposed, version_info = check_api_exposure(host, port)
  if api_exposed then
    vuln_count = vuln_count + 1
    table.insert(output, "Docker API exposed without authentication")
    if version_info then
      local version = version_info:match('"Version":"([^"]+)"')
      if version then
        table.insert(output, "  Docker version: " .. version)
      end
    end
  end

  local containers_found, container_list = list_containers(host, port)
  if containers_found then
    table.insert(output, "")
    table.insert(output, "Containers found: " .. (container_list:match("%[") and "yes" or "no"))

    if container_list:match('"Privileged":true') then
      vuln_count = vuln_count + 1
      table.insert(output, "Privileged containers detected")
    end

    local mounts = check_mounts(container_list)
    if #mounts > 0 then
      vuln_count = vuln_count + 1
      table.insert(output, "Sensitive mounts found:")
      for _, mount in ipairs(mounts) do
        table.insert(output, "  - " .. mount)
      end
    end

    local caps = check_capabilities(container_list)
    if #caps > 0 then
      vuln_count = vuln_count + 1
      table.insert(output, "Dangerous capabilities: " .. table.concat(caps, ", "))
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Docker Escape Risks:")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    table.insert(result, "")
    table.insert(result, "Recommendation: Restrict Docker API access")
    table.insert(result, "Recommendation: Use TLS client certificate authentication")
    table.insert(result, "Recommendation: Avoid privileged containers")
    return table.concat(result, "\n")
  end

  return "No Docker escape vulnerabilities detected"
end
