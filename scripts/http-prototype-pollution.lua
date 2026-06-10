-- Prototype Pollution Detection
-- Checks for JavaScript prototype pollution vulnerabilities
-- @output
-- 80/tcp open  http
-- | http-prototype-pollution:
-- |   WARNING: Prototype pollution indicators found
-- |     JSON input accepts __proto__ property
-- |_    Potential for property injection

description = [[
Detects JavaScript prototype pollution vulnerabilities.
Checks if web applications accept malicious __proto__, constructor,
or prototype properties in JSON input.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "http"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local vulns = {}

    local api_paths = {
        "/api", "/api/v1", "/api/user", "/api/data",
        "/graphql", "/query", "/search", "/process"
    }

    for _, path in ipairs(api_paths) do
        local payloads = {
            '{"__proto__": {"isAdmin": true}}',
            '{"constructor": {"prototype": {"isAdmin": true}}}',
            '{"__proto__": {"toString": "polluted"}}',
        }

        for _, payload in ipairs(payloads) do
            local options = {
                header = {
                    ["Content-Type"] = "application/json"
                }
            }
            local response = http.post(host, port, path, options, nil, payload)
            if response and response.status then
                if response.status == 200 or response.status == 201 then
                    if response.body then
                        if response.body:find("isAdmin") or
                           response.body:find("polluted") then
                            table.insert(vulns, "Prototype pollution possible on: " .. path)
                        end
                    end
                end
            end
        end

        local query_payloads = {
            path .. "?__proto__[isAdmin]=true",
            path .. "?constructor[prototype][isAdmin]=true",
            path .. "?__proto__.isAdmin=true",
        }

        for _, qp in ipairs(query_payloads) do
            local response = http.get(host, port, qp)
            if response and response.status == 200 and response.body then
                if response.body:find("isAdmin.*true") then
                    table.insert(vulns, "Query-based prototype pollution on: " .. path)
                end
            end
        end
    end

    if #vulns > 0 then
        local result = "WARNING: Prototype pollution indicators found\n"
        result = result .. "  JSON input accepts __proto__ property\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "No prototype pollution vulnerabilities detected"
end
