local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Analyzes ETag headers for information disclosure.
ETags may leak inode numbers, file sizes, timestamps, or server internals.
]]

---
-- @usage
-- nmap --script http-etag -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-etag:
-- |   ETag Analysis:
-- |     ETag: "5f3a2b-1234-5a1b2c3d"
-- |     Format: Apache (inode-size-timestamp)
-- |   [!] ETag may disclose inode number and file metadata

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function analyze_etag(etag)
  local info = {}

  -- Apache format: inode-size-timestamp
  if string.match(etag, '^"%x+-%x+-%x+"$') then
    info.format = "Apache (inode-size-timestamp)"
    info.disclosure = "inode number, file size, last modification time"
    -- Apache format: "inode-size-mtime"
    local inode, size, mtime = string.match(etag, '^"(%x+)-(%x+)-(%x+)"$')
    if inode then
      info.parsed = string.format("Inode: %s, Size: %d bytes, Mtime: %s",
        inode, tonumber(size, 16), mtime)
    end
  -- IIS format: Filetimestamp:ChangeNumber
  elseif string.match(etag, '^"%d+:%d+"$') then
    info.format = "IIS (timestamp:changenumber)"
    info.disclosure = "file timestamp and change number"
    local ts, change = string.match(etag, '^"(%d+):(%d+)"$')
    if ts then
      info.parsed = string.format("Timestamp: %s, Change: %s", ts, change)
    end
  -- Nginx weak ETag
  elseif string.match(etag, '^W/"') then
    info.format = "Nginx weak ETag"
    info.disclosure = "minimal (weak validator)"
  -- UUID-based
  elseif string.match(etag, '^"%x%x%x%x%x%x%x%x%-%x%x%x%x%-') then
    info.format = "UUID-based"
    info.disclosure = "minimal"
  else
    info.format = "Unknown"
    info.disclosure = "potential metadata"
  end

  return info
end

action = function(host, port)
  local paths = {"/", "/index.html", "/favicon.ico"}
  local output = {}
  local found_etag = false

  for _, path in ipairs(paths) do
    local response = http.get(host, port, path)

    if response and response.header then
      local etag = response.header["etag"]

      if etag then
        found_etag = true
        local info = analyze_etag(etag)

        table.insert(output, string.format("Path: %s", path))
        table.insert(output, string.format("  ETag: %s", etag))
        table.insert(output, string.format("  Format: %s", info.format))
        if info.parsed then
          table.insert(output, string.format("  Parsed: %s", info.parsed))
        end
        table.insert(output, string.format("  Disclosure Risk: %s", info.disclosure))
        table.insert(output, "")
      end
    end
  end

  if found_etag then
    local result = {}
    table.insert(result, "ETag Analysis:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end

    table.insert(result, "Recommendations:")
    table.insert(result, "  [!] Review ETag format to prevent information leakage")
    table.insert(result, "  [!] Consider using weak ETags or hash-based ETags")

    return table.concat(result, "\n")
  end

  return "No ETag headers found"
end
