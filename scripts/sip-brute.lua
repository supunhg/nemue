local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Brute forces SIP extensions/extensions on SIP services.
Tests common SIP extensions by sending OPTIONS requests.
]]

---
-- @usage
-- nmap --script sip-brute -p 5060 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 5060/udp open  sip
-- | sip-brute:
-- |   Valid SIP extensions found:
-- |     100 (Asterisk PBX)
-- |     101 (User)
-- |     200 (Conference)
-- |_  Use --script-args sip-brute.threads=4 for faster scanning

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"intrusive", "brute"}

portrule = shortport.port_or_service(5060, "sip")

local common_extensions = {
  "100", "101", "102", "103", "104", "105",
  "200", "201", "202",
  "300", "301",
  "400", "500", "600", "700", "800", "900",
  "1000", "2000", "3000",
  "admin", "operator", "voicemail", "conference",
  "test", "demo", "support", "sales",
  "10000", "9999"
}

local function create_sip_options(extension, host)
  local request = string.format(
    "OPTIONS sip:%s@%s SIP/2.0\r\n" ..
    "Via: SIP/2.0/UDP %s:5060;branch=z9hG4bK-%s\r\n" ..
    "From: <sip:nmap@%s>;tag=%s\r\n" ..
    "To: <sip:%s@%s>\r\n" ..
    "Call-ID: %s@%s\r\n" ..
    "CSeq: 1 OPTIONS\r\n" ..
    "Contact: <sip:nmap@%s:5060>\r\n" ..
    "Max-Forwards: 70\r\n" ..
    "User-Agent: Nmap SIP Scanner\r\n" ..
    "Content-Length: 0\r\n" ..
    "\r\n",
    extension, host.ip,
    host.ip, tostring(os.time()),
    host.ip, tostring(math.random(100000, 999999)),
    extension, host.ip,
    tostring(os.time()), host.ip,
    host.ip
  )
  return request
end

local function test_extension(host, port, extension)
  local socket = nmap.new_socket()
  socket:set_timeout(3000)

  local status, err = socket:connect(host.ip, port, "udp")
  if not status then
    return false, nil
  end

  local request = create_sip_options(extension, host)
  socket:send(request)

  local status, response = socket:receive()
  socket:close()

  if status and response then
    if response:match("SIP/2%.0 200") or response:match("SIP/2%.0 401") or response:match("SIP/2%.0 407") then
      local server = response:match("Server:%s*([^\r\n]+)")
      return true, server
    end
  end

  return false, nil
end

action = function(host, port)
  local output = {}
  local found = 0

  for _, extension in ipairs(common_extensions) do
    local valid, server = test_extension(host, port, extension)
    if valid then
      found = found + 1
      if server then
        table.insert(output, string.format("%s (%s)", extension, server:trim()))
      else
        table.insert(output, extension)
      end
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Valid SIP extensions found:")
    for _, line in ipairs(output) do
      table.insert(result, "  " .. line)
    end
    table.insert(result, string.format("\nTotal found: %d", found))
    return table.concat(result, "\n")
  end

  return "No valid SIP extensions found"
end
