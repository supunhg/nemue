-- HTTP CORS Misconfiguration Check
-- Tests for Cross-Origin Resource Sharing issues

local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks for CORS misconfigurations including wildcard origins,
null origin reflection, and credential exposure risks.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or port.number == 8080)
end

action = function(host, port)
    local output = {}
    local issues = {}

    local test_origin = "https://evil.com"
    local options = {
        header = {
            Origin = test_origin
        }
    }

    local response = http.get(host, port, "/", options)

    if response and response.header then
        local allow_origin = response.header["access-control-allow-origin"]
        local allow_creds = response.header["access-control-allow-credentials"]

        if allow_origin == "*" then
            table.insert(issues, "Access-Control-Allow-Origin set to wildcard (*)")
            if allow_creds == "true" then
                table.insert(issues, "CRITICAL: Credentials allowed with wildcard origin")
            end
        elseif allow_origin == test_origin then
            table.insert(issues, "Origin reflection detected: " .. test_origin)
        end

        options.header.Origin = "null"
        local null_resp = http.get(host, port, "/", options)
        if null_resp and null_resp.header then
            if null_resp.header["access-control-allow-origin"] == "null" then
                table.insert(issues, "Null origin accepted (sandbox escape risk)")
            end
        end
    end

    if #issues > 0 then
        table.insert(output, "CORS Misconfiguration Found:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    else
        table.insert(output, "No CORS misconfiguration detected")
    end

    return stdnse.format_output(true, output)
end
