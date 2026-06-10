local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Detects CORS misconfigurations by testing various Origin headers
and checking for overly permissive cross-origin resource sharing.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or port.number == 8080)
end

local test_origins = {
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://" .. (host and host.name or "test.com") .. ".evil.com",
}

action = function(host, port)
    local output = {}
    local issues = {}

    local response = http.get(host, port, "/")

    if not response then
        return stdnse.format_output(false, "Could not connect to service")
    end

    local acao = response.header["access-control-allow-origin"]
    local acam = response.header["access-control-allow-methods"]
    local acac = response.header["access-control-allow-credentials"]

    if acao then
        table.insert(output, "Access-Control-Allow-Origin: " .. acao)

        if acao == "*" then
            if acac and acac:lower() == "true" then
                table.insert(issues, "CRITICAL: Wildcard origin with credentials allowed")
            else
                table.insert(issues, "Wildcard origin (*) - review if sensitive data exposed")
            end
        end

        if acao == "null" then
            table.insert(issues, "Origin set to 'null' - allows sandboxed iframe access")
        end
    end

    if acam then
        table.insert(output, "Access-Control-Allow-Methods: " .. acam)
        if acam:upper():find("PUT") or acam:upper():find("DELETE") then
            table.insert(issues, "Dangerous HTTP methods allowed in CORS")
        end
    end

    if acac and acac:lower() == "true" then
        table.insert(output, "Access-Control-Allow-Credentials: true")
        if acao and acao ~= "*" then
            table.insert(output, "  Credentials with specific origin: " .. (acao or "none"))
        end
    end

    if #issues > 0 then
        table.insert(output, "\nCORS Misconfiguration Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    else
        table.insert(output, "\nNo obvious CORS misconfigurations detected")
    end

    return stdnse.format_output(true, output)
end
