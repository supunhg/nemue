local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Performs LDAP search base detection and enumeration.
Identifies accessible LDAP naming contexts and base DNs.
]]

---
-- @usage
-- nmap --script ldap-search -p 389,636 <target>
--
-- @output
-- PORT    STATE SERVICE
-- 389/tcp open  ldap
-- | ldap-search:
-- |   Base DNs found:
-- |     dc=example,dc=com
-- |     dc=internal,dc=corp
-- |   Naming contexts:
-- |     dc=example,dc=com (default)
-- |_    dc=internal,dc=corp

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.port_or_service(389, "ldap")

local function create_bind_request()
  local packet = "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
  return packet
end

local function create_search_request(base_dn)
  local base_len = #base_dn
  local packet = string.format(
    "\x30\x25\x02\x01\x02\x63\x20\x04%s%s\x0a\x01\x00\x0a\x01\x00" ..
    "\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa0\x07\x89\x05%s\x30\x00",
    string.char(base_len),
    base_dn,
    "objectClass"
  )
  return packet
end

local function parse_ldap_response(data)
  if #data < 10 then
    return nil
  end

  local contexts = {}
  local pos = 1

  while pos <= #data do
    local dn_match = data:match("dc=[%w]+,dc=[%w]+", pos)
    if dn_match then
      table.insert(contexts, dn_match)
      pos = pos + #dn_match
    else
      break
    end
  end

  return contexts
end

local function try_bind(host, port)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local bind_request = create_bind_request()
  socket:send(bind_request)

  local status, response = socket:receive()
  if not status then
    socket:close()
    return nil
  end

  socket:close()
  return response
end

local function search_base(host, port, base_dn)
  local socket = nmap.new_socket()
  socket:set_timeout(5000)

  local status, err = socket:connect(host.ip, port)
  if not status then
    return nil
  end

  local bind_request = create_bind_request()
  socket:send(bind_request)
  socket:receive()

  local search_request = create_search_request(base_dn)
  socket:send(search_request)

  local results = {}
  repeat
    local status, data = socket:receive()
    if status and #data > 0 then
      local contexts = parse_ldap_response(data)
      if contexts then
        for _, ctx in ipairs(contexts) do
          table.insert(results, ctx)
        end
      end
    end
  until not status

  socket:close()
  return results
end

action = function(host, port)
  local base_dns = {
    "",
    "dc=com",
    "dc=org",
    "dc=net",
    "dc=local",
    "dc=internal",
    "dc=corp",
    "dc=lan"
  }

  local output = {}
  local found_contexts = {}

  for _, base_dn in ipairs(base_dns) do
    local results = search_base(host, port, base_dn)
    if results then
      for _, ctx in ipairs(results) do
        if not found_contexts[ctx] then
          found_contexts[ctx] = true
          table.insert(output, ctx)
        end
      end
    end
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Base DNs found:")
    for _, dn in ipairs(output) do
      table.insert(result, "  " .. dn)
    end
    return table.concat(result, "\n")
  end

  return "No LDAP base DNs discovered"
end
