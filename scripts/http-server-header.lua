-- HTTP Server Header Detection
-- Extracts the Server header from HTTP responses

local nmap = require "nmap"
local http = require "http"

description = [[
Extracts and displays the Server header from HTTP responses.
]]

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
           (port.service == "http" or port.service == "https" or 
            port.number == 80 or port.number == 443 or port.number == 8080)
end

action = function(host, port)
    local response = http.get(host.ip, port.number, "/")
    
    if response and response.headers and response.headers["server"] then
        return response.headers["server"]
    end
    
    return nil
end
