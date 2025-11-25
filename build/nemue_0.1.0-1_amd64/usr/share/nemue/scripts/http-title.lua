-- HTTP Title Extraction
-- Extracts the <title> tag from HTML pages

local nmap = require "nmap"
local http = require "http"

description = [[
Extracts and displays the HTML title from web pages.
]]

categories = {"default", "discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and port.state == "open" and
           (port.service == "http" or port.service == "https" or 
            port.number == 80 or port.number == 443 or port.number == 8080)
end

action = function(host, port)
    local response = http.get(host.ip, port.number, "/")
    
    if response and response.body then
        local title = response.body:match("<title>(.-)</title>")
        if title then
            -- Clean up whitespace
            title = title:gsub("^%s+", ""):gsub("%s+$", ""):gsub("%s+", " ")
            return title
        end
    end
    
    return nil
end
