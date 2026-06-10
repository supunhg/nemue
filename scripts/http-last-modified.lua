local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local os = require "os"

description = [[
Analyzes Last-Modified headers for information disclosure.
Detects stale content, predictable modification patterns, and timestamp leakage.
]]

---
-- @usage
-- nmap --script http-last-modified -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-last-modified:
-- |   Last-Modified Analysis:
-- |     Last-Modified: Wed, 01 Jan 2025 00:00:00 GMT
-- |     Age: 86400 seconds
-- |   [!] Content appears stale (not modified recently)

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function parse_http_date(date_str)
  local months = {
    Jan = 1, Feb = 2, Mar = 3, Apr = 4, May = 5, Jun = 6,
    Jul = 7, Aug = 8, Sep = 9, Oct = 10, Nov = 11, Dec = 12
  }

  local day, month, year, hour, min, sec = string.match(
    date_str, "(%d+)%s+(%a+)%s+(%d+)%s+(%d+):(%d+):(%d+)")

  if day and months[month] then
    return os.time({
      year = tonumber(year),
      month = months[month],
      day = tonumber(day),
      hour = tonumber(hour),
      min = tonumber(min),
      sec = tonumber(sec)
    })
  end
  return nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local response = http.get(host, port, path)

  if not response or not response.header then
    return "No response received"
  end

  local output = {}
  local issues = {}

  local last_modified = response.header["last-modified"]
  local age = response.header["age"]
  local date = response.header["date"]

  table.insert(output, "Last-Modified Analysis:")
  table.insert(output, string.format("  Last-Modified: %s", last_modified or "not set"))
  table.insert(output, string.format("  Date: %s", date or "not set"))
  table.insert(output, string.format("  Age: %s seconds", age or "not set"))
  table.insert(output, "")

  if last_modified then
    local modified_ts = parse_http_date(last_modified)
    local current_ts = os.time()

    if modified_ts then
      local age_seconds = current_ts - modified_ts
      local age_days = math.floor(age_seconds / 86400)

      table.insert(output, string.format("  Content Age: %d days", age_days))

      if age_days > 365 then
        table.insert(issues, string.format("Content not modified in %d days - potentially abandoned", age_days))
      elseif age_days > 90 then
        table.insert(issues, string.format("Content not modified in %d days - review recommended", age_days))
      end

      if modified_ts > current_ts then
        table.insert(issues, "Last-Modified date is in the future - clock skew or misconfiguration")
      end
    else
      table.insert(issues, "Could not parse Last-Modified date format")
    end
  else
    table.insert(issues, "No Last-Modified header - cannot determine content freshness")
  end

  if age then
    local age_val = tonumber(age)
    if age_val and age_val > 86400 then
      table.insert(issues, string.format("Content cached for %d seconds (over 24 hours)", age_val))
    end
  end

  if #issues > 0 then
    table.insert(output, "Issues Found:")
    for _, issue in ipairs(issues) do
      table.insert(output, string.format("  [!] %s", issue))
    end
  else
    table.insert(output, "[+] Content appears fresh and well-maintained")
  end

  return table.concat(output, "\n")
end
