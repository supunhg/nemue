local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects JWT (JSON Web Token) usage in HTTP communications.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/")

  if response then
    local auth = response.header["authorization"]
    if auth and auth:match("^Bearer ") then
      local token = auth:match("^Bearer (.+)")
      if token and token:match("^[A-Za-z0-9%-_]+%.") then
        table.insert(result, "JWT token detected in Authorization header")
      end
    end

    local cookies = response.header["set-cookie"]
    if cookies then
      for cookie in cookies:gmatch("[^,]+") do
        if cookie:match("eyJ[A-Za-z0-9%-_]+%.") then
          table.insert(result, "JWT token detected in cookie")
        end
      end
    end

    local body = response.body or ""
    if body:match("eyJ[A-Za-z0-9%-_]+%.") then
      table.insert(result, "JWT token pattern found in response body")
    end

    if #result == 0 then
      table.insert(result, "No JWT tokens detected")
    end
  end

  return stdnse.format_output(true, result)
end
