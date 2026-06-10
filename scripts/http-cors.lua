local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Checks for Cross-Origin Resource Sharing (CORS) configuration.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local response = http.get(host, port, "/")

  if response then
    local acao = response.header["access-control-allow-origin"]
    local acam = response.header["access-control-allow-methods"]
    local acac = response.header["access-control-allow-credentials"]

    table.insert(result, "CORS Configuration:")
    if acao then
      table.insert(result, "Access-Control-Allow-Origin: " .. acao)
      if acao == "*" then
        table.insert(result, "WARNING: Wildcard origin allowed")
      end
    else
      table.insert(result, "No CORS headers detected")
    end
    if acam then
      table.insert(result, "Access-Control-Allow-Methods: " .. acam)
    end
    if acac then
      table.insert(result, "Access-Control-Allow-Credentials: " .. acac)
    end
  end

  return stdnse.format_output(true, result)
end
