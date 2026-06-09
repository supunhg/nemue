local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local url = require "url"

description = [[
Detects Open Redirect vulnerabilities in web applications.
Tests redirect parameters with external URLs to identify unvalidated redirects.
]]

---
-- @usage
-- nmap --script http-open-redirect -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-open-redirect:
-- |   Open Redirect Vulnerability:
-- |     Parameter: redirect
-- |     URL: /login?redirect=http://evil.com
-- |     Redirects to: http://evil.com
-- |_  Use --script-args http-open-redirect.url=<url> to test specific page

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local redirect_params = {
  "url", "redirect", "redirect_url", "redirect_uri", "return", "return_url",
  "return_to", "next", "next_url", "goto", "go", "target", "dest",
  "destination", "redir", "redirect_to", "checkout_url", "continue",
  "return_path", "location", "to", "out", "view", "dir", "show",
  "navigation", "open", "link", "forward", "forward_url"
}

local test_domain = "http://evil.com"
local test_paths = {
  "//evil.com",
  "////evil.com",
  "http://evil.com",
  "https://evil.com",
  "//evil.com/%2e%2e",
  "/evil.com",
  "evil.com",
  "http://evil.com%00.example.com",
  "http://evil.com%252f%252f.example.com"
}

local function check_redirect(host, port, path, param, test_url)
  local request_path = path .. "?" .. param .. "=" .. url.escape(test_url)
  local response = http.get(host, port, request_path)

  if response then
    if response.status == 301 or response.status == 302 or
       response.status == 303 or response.status == 307 or
       response.status == 308 then
      local location = response.header["location"]
      if location and location:match("evil%.com") then
        return true, location
      end
    end

    if response.body and response.body:match("evil%.com") then
      local meta_refresh = response.body:match('url=([^"\'>]+)')
      if meta_refresh and meta_refresh:match("evil%.com") then
        return true, meta_refresh
      end
    end
  end
  return false, nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local vuln_count = 0

  for _, param in ipairs(redirect_params) do
    for _, test_path in ipairs(test_paths) do
      local vulnerable, redirect_location = check_redirect(host, port, path, param, test_path)

      if vulnerable then
        vuln_count = vuln_count + 1
        table.insert(output, string.format("Parameter: %s", param))
        table.insert(output, string.format("Test URL: %s", test_path))
        table.insert(output, string.format("Redirects to: %s", redirect_location))
        table.insert(output, "")
        break
      end
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Open Redirect Vulnerabilities Found:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    return table.concat(result, "\n")
  end

  return "No open redirect vulnerabilities detected"
end
