local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects WebSocket endpoints and upgrade support.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local headers = {
    ["Upgrade"] = "websocket",
    ["Connection"] = "Upgrade",
    ["Sec-WebSocket-Key"] = "dGhlIHNhbXBsZSBub25jZQ==",
    ["Sec-WebSocket-Version"] = "13",
  }

  local response = http.get(host, port, "/", {header = headers})

  if response then
    if response.status == 101 then
      table.insert(result, "WebSocket: Supported")
      local accept = response.header["sec-websocket-accept"]
      if accept then
        table.insert(result, "Sec-WebSocket-Accept: " .. accept)
      end
    elseif response.status == 400 then
      table.insert(result, "WebSocket: Endpoint exists but requires valid request")
    else
      table.insert(result, "WebSocket: Not supported (status: " .. response.status .. ")")
    end
  end

  return stdnse.format_output(true, result)
end
