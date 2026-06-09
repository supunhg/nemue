local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Tests for HTTP Request Smuggling vulnerabilities (CL.TE, TE.CL, TE.TE).
Detects inconsistencies in how front-end and back-end servers handle Content-Length and Transfer-Encoding.
]]

---
-- @usage
-- nmap --script http-request-smuggling -p 80,443 <target>
--
-- @output
-- PORT   STATE SERVICE
-- 80/tcp open  http
-- | http-request-smuggling:
-- |   Potential HTTP Request Smuggling:
-- |     Type: CL.TE
-- |     Front-end uses Content-Length, back-end uses Transfer-Encoding
-- |_  Consider testing manually with specialized tools

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.http

local function send_raw_request(host, port, raw_request)
  local socket = nmap.new_socket()
  local timeout = 10000

  socket:set_timeout(timeout)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil, err
  end

  socket:send(raw_request)

  local response = ""
  local partial = ""
  repeat
    status, partial = socket:receive()
    if status then
      response = response .. partial
    end
  until not status

  socket:close()
  return response
end

local function test_cl_te(host, port, path)
  local raw_request = string.format(
    "POST %s HTTP/1.1\r\n" ..
    "Host: %s\r\n" ..
    "Content-Length: 6\r\n" ..
    "Transfer-Encoding: chunked\r\n" ..
    "\r\n" ..
    "0\r\n" ..
    "\r\n" ..
    "X",
    path, host.ip
  )

  local response = send_raw_request(host, port, raw_request)
  if response and response:match("HTTP/1%.1 400") then
    return true, "CL.TE"
  end
  return false, nil
end

local function test_te_cl(host, port, path)
  local raw_request = string.format(
    "POST %s HTTP/1.1\r\n" ..
    "Host: %s\r\n" ..
    "Content-Length: 3\r\n" ..
    "Transfer-Encoding: chunked\r\n" ..
    "\r\n" ..
    "8\r\n" ..
    "SMUGGLED\r\n" ..
    "0\r\n" ..
    "\r\n",
    path, host.ip
  )

  local response = send_raw_request(host, port, raw_request)
  if response and response:match("HTTP/1%.1 200") then
    return true, "TE.CL"
  end
  return false, nil
end

local function test_te_te(host, port, path)
  local raw_request = string.format(
    "POST %s HTTP/1.1\r\n" ..
    "Host: %s\r\n" ..
    "Transfer-Encoding: chunked\r\n" ..
    "Transfer-Encoding: cow\r\n" ..
    "\r\n" ..
    "5\r\n" ..
    "SMUGGLED\r\n" ..
    "0\r\n" ..
    "\r\n",
    path, host.ip
  )

  local response = send_raw_request(host, port, raw_request)
  if response then
    return true, "TE.TE"
  end
  return false, nil
end

action = function(host, port)
  local path = stdnse.get_script_args(SCRIPT_NAME .. ".url") or "/"
  local output = {}
  local vuln_count = 0

  local tests = {
    {func = test_cl_te, name = "CL.TE"},
    {func = test_te_cl, name = "TE.CL"},
    {func = test_te_te, name = "TE.TE"}
  }

  for _, test in ipairs(tests) do
    local vulnerable, smuggling_type = test.func(host, port, path)

    if vulnerable then
      vuln_count = vuln_count + 1
      table.insert(output, string.format("Type: %s", smuggling_type))
      table.insert(output, string.format("Test: %s", test.name))
      table.insert(output, "")
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Potential HTTP Request Smuggling:")
    table.insert(result, "")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    table.insert(result, "Consider testing manually with specialized tools")
    return table.concat(result, "\n")
  end

  return "No HTTP request smuggling vulnerabilities detected"
end
