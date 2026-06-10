local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Analyzes cookie security flags including Secure, HttpOnly, and SameSite.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/")

  if response then
    local cookies = response.header["set-cookie"]
    if cookies then
      table.insert(result, "Cookie Analysis:")
      for cookie in cookies:gmatch("[^,]+") do
        local name = cookie:match("^%s*(%S-)=")
        if name then
          table.insert(result, "Cookie: " .. name)
          if cookie:match("[Ss]ecure") then
            table.insert(result, "  Secure: Yes")
          else
            table.insert(result, "  Secure: No (WARNING)")
          end
          if cookie:match("[Hh]ttp[Oo]nly") then
            table.insert(result, "  HttpOnly: Yes")
          else
            table.insert(result, "  HttpOnly: No (WARNING)")
          end
          local ss = cookie:match("[Ss]ame[Ss]ite=(%S+)")
          if ss then
            table.insert(result, "  SameSite: " .. ss)
          else
            table.insert(result, "  SameSite: Not set")
          end
        end
      end
    else
      table.insert(result, "No cookies detected")
    end
  end

  return stdnse.format_output(true, result)
end
