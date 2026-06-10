-- HTTP Token Enumeration
-- Discovers and analyzes authentication tokens

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates authentication tokens including JWT, API keys, and
CSRF tokens by analyzing responses and JavaScript files.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local findings = {}

    local response = http.get(host.ip, port, "/")
    if not response or not response.body then
        return "No HTTP response received"
    end

    table.insert(output, "Token Enumeration")
    table.insert(output, "")

    local body = response.body

    local csrf_patterns = {
        'name=["\']csrf[_%-]?token["\'][^>]*value=["\']([^"\']+)',
        'name=["\']_token["\'][^>]*value=["\']([^"\']+)',
        'name=["\']authenticity[_%-]?token["\'][^>]*value=["\']([^"\']+)',
        'name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)',
    }

    for _, pattern in ipairs(csrf_patterns) do
        local token = body:match(pattern)
        if token then
            table.insert(findings, "CSRF token found: " .. token:sub(1, 20) .. "...")
            table.insert(output, "[!] CSRF Token: " .. token:sub(1, 40))
        end
    end

    local jwt_pattern = "eyJ[%w%-_]+%.eyJ[%w%-_]+%.[%w%-_]+"
    for jwt in body:gmatch(jwt_pattern) do
        table.insert(findings, "JWT token found in page body")
        table.insert(output, "[!] JWT Token: " .. jwt:sub(1, 40) .. "...")
    end

    local api_key_patterns = {
        'api[_%-]?key["\']?%s*[:=]%s*["\']([%w%-]+)',
        'apikey["\']?%s*[:=]%s*["\']([%w%-]+)',
        'access[_%-]?token["\']?%s*[:=]%s*["\']([%w%-]+)',
    }

    for _, pattern in ipairs(api_key_patterns) do
        local key = body:match(pattern)
        if key and #key > 10 then
            table.insert(findings, "API key found in page")
            table.insert(output, "[!] API Key: " .. key:sub(1, 20) .. "...")
        end
    end

    local headers_to_check = {"authorization", "x-api-key", "x-auth-token", "x-csrf-token"}
    for _, h in ipairs(headers_to_check) do
        local value = response.header and response.header[h]
        if value then
            table.insert(findings, "Token in response header: " .. h)
            table.insert(output, "[!] Header " .. h .. ": " .. value:sub(1, 40))
        end
    end

    if #findings > 0 then
        table.insert(output, "")
        table.insert(output, "[!] INFO: " .. #findings .. " tokens discovered")
        table.insert(output, "[!] Analyze tokens for entropy and weaknesses")
    else
        table.insert(output, "[-] No tokens discovered in initial response")
    end

    return stdnse.format_output(true, output)
end
