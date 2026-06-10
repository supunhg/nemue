local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects Cross-Site Request Forgery (CSRF) vulnerabilities in web applications.
Checks for missing or weak anti-CSRF tokens in forms and state-changing requests.
]]

---
-- @usage
-- nmap --script http-csrf -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-csrf:
-- |   Vulnerable forms found:
-- |     Path: /transfer
-- |       Form method: POST
-- |       Missing CSRF token
-- |     Path: /password-change
-- |       Form method: POST
-- |       Weak CSRF token (predictable)
-- |_  Use --script-args http-csrf.url=<url> to test specific pages

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local csrf_token_names = {
  "csrf", "csrftoken", "csrf_token", "_csrf", "xsrf", "xsrf_token",
  "anti-csrf", "token", "_token", "authenticity_token", "__requestverificationtoken",
  "nonce", "_nonce", "form_token", "form_build_id", "verification_token"
}

local function find_forms(body)
  local forms = {}
  for form_action, form_method, form_body in body:gmatch('<form[^>]-action=["\']([^"\']*)["\'][^>]-method=["\']([^"\']*)["\']([^>]*)>(.-)</form>') do
    table.insert(forms, {
      action = form_action,
      method = form_method:upper(),
      body = form_body
    })
  end
  return forms
end

local function check_csrf_token(form_body)
  local has_token = false
  local token_name = nil
  local token_value = nil

  for _, name in ipairs(csrf_token_names) do
    local pattern = 'name=["\']' .. name .. '["\'][^>]-value=["\']([^"\']*)["\']'
    local value = form_body:match(pattern)
    if value then
      has_token = true
      token_name = name
      token_value = value
      break
    end
  end

  return has_token, token_name, token_value
end

local function analyze_token_strength(token_value)
  if not token_value then return "none" end
  if #token_value < 8 then return "weak" end
  if token_value:match("^%d+$") then return "weak" end
  if token_value:match("^%d+-%d+$") then return "weak" end
  return "strong"
end

action = function(host, port)
  local url = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local vuln_count = 0

  local response = http.get(host, port, url)
  if not response or not response.body then
    return nil
  end

  local forms = find_forms(response.body)

  for _, form in ipairs(forms) do
    if form.method == "POST" or form.method == "PUT" or form.method == "DELETE" then
      local has_token, token_name, token_value = check_csrf_token(form.body)
      local token_strength = analyze_token_strength(token_value)

      local issue = {
        path = url,
        action = form.action,
        method = form.method
      }

      if not has_token then
        issue.status = "Missing CSRF token"
        issue.severity = "HIGH"
        vuln_count = vuln_count + 1
      elseif token_strength == "weak" then
        issue.status = "Weak CSRF token: " .. token_name .. "=" .. token_value
        issue.severity = "MEDIUM"
        vuln_count = vuln_count + 1
      end

      if issue.status then
        table.insert(output, string.format("Path: %s", issue.path))
        table.insert(output, string.format("  Action: %s", issue.action or "same"))
        table.insert(output, string.format("  Method: %s", issue.method))
        table.insert(output, string.format("  Status: %s", issue.status))
        table.insert(output, string.format("  Severity: %s", issue.severity))
      end
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "CSRF Vulnerabilities Found:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    return table.concat(result, "\n")
  end

  return "No CSRF vulnerabilities detected"
end
