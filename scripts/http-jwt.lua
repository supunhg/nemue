-- HTTP JWT Token Detection
-- Detects JWT tokens in HTTP responses and analyzes their contents

local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")
local base64 = require("base64")
local json = require("json")

description = [[
Scans HTTP responses for JWT (JSON Web Token) tokens in headers,
cookies, and response bodies. Attempts to decode and display token
claims without verifying the signature.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

local function decode_jwt_segment(segment)
    local padded = segment
    local mod = #padded % 4
    if mod == 2 then
        padded = padded .. "=="
    elseif mod == 3 then
        padded = padded .. "="
    end

    local decoded = base64.dec(padded)
    if not decoded then
        return nil
    end

    local status, parsed = json.parse(decoded)
    if status then
        return parsed
    end
    return decoded
end

local function find_jwt_tokens(text)
    local tokens = {}
    for token in text:gmatch("eyJ[%w_-]+%.eyJ[%w_-]+%.[%w_-]+") do
        table.insert(tokens, token)
    end
    return tokens
end

action = function(host, port)
    local results = {}
    local paths = { "/", "/api", "/login", "/auth", "/index.html" }

    for _, path in ipairs(paths) do
        local response = http.get(host, port, path)
        if response then
            local tokens = {}

            if response.header then
                for _, header_name in ipairs({"Authorization", "Set-Cookie", "X-Auth-Token", "X-Access-Token"}) do
                    local val = response.header[header_name]
                    if val then
                        for _, token in ipairs(find_jwt_tokens(val)) do
                            table.insert(tokens, {token = token, source = header_name .. " header"})
                        end
                    end
                end
            end

            if response.body then
                for _, token in ipairs(find_jwt_tokens(response.body)) do
                    table.insert(tokens, {token = token, source = "response body"})
                end
            end

            for _, entry in ipairs(tokens) do
                table.insert(results, "JWT found in " .. entry.source .. " at " .. path)

                local parts = {}
                for part in entry.token:gmatch("([^%.]+)") do
                    table.insert(parts, part)
                end

                if #parts >= 2 then
                    local header = decode_jwt_segment(parts[1])
                    local payload = decode_jwt_segment(parts[2])

                    if header then
                        if type(header) == "table" then
                            table.insert(results, "  Header: alg=" .. (header.alg or "N/A") .. ", typ=" .. (header.typ or "N/A"))
                        end
                    end

                    if payload then
                        if type(payload) == "table" then
                            if payload.sub then table.insert(results, "  Subject: " .. tostring(payload.sub)) end
                            if payload.iss then table.insert(results, "  Issuer: " .. tostring(payload.iss)) end
                            if payload.exp then table.insert(results, "  Expires: " .. tostring(payload.exp)) end
                            if payload.iat then table.insert(results, "  Issued: " .. tostring(payload.iat)) end
                        end
                    end
                end
            end
        end
    end

    if #results == 0 then
        return nil
    end

    return stdnse.format_output(true, results)
end
