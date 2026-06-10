-- GraphQL Injection Detection
-- Tests for GraphQL injection and introspection vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for GraphQL injection vulnerabilities including introspection
queries, batch queries, and injection through GraphQL parameters.
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

    local graphql_paths = {"/graphql", "/graphiql", "/api/graphql", "/v1/graphql", "/query"}

    for _, path in ipairs(graphql_paths) do
        local introspection_query = '{"query":"{ __schema { types { name } } }"}'
        local headers = {["Content-Type"] = "application/json"}
        local r = http.post(host.ip, port, path, headers, nil, introspection_query)

        if r and r.status == 200 and r.body then
            if r.body:find("__schema") or r.body:find("types") then
                table.insert(findings, {
                    endpoint = path,
                    type = "Introspection enabled",
                    severity = "MEDIUM"
                })

                local full_query = '{"query":"{ __schema { queryType { fields { name args { name type { name } } } } mutationType { fields { name } } } }"}'
                local r2 = http.post(host.ip, port, path, headers, nil, full_query)
                if r2 and r2.body and r2.body:find("fields") then
                    table.insert(findings, {
                        endpoint = path,
                        type = "Full schema introspection",
                        severity = "HIGH"
                    })
                end
            end

            local dos_query = '{"query":"query { __typename ...on Query { __typename } }"}'
            local r3 = http.post(host.ip, port, path, headers, nil, dos_query)
            if r3 and r3.status == 200 then
                table.insert(findings, {
                    endpoint = path,
                    type = "Query endpoint accessible",
                    severity = "INFO"
                })
            end

            local batch_query = '[{"query":"{ __typename }"},{"query":"{ __typename }"}]'
            local r4 = http.post(host.ip, port, path, headers, nil, batch_query)
            if r4 and r4.status == 200 and r4.body and r4.body:find("%[%{") then
                table.insert(findings, {
                    endpoint = path,
                    type = "Batch queries allowed",
                    severity = "MEDIUM"
                })
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "GraphQL Injection/Configuration Issues Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] Endpoint: " .. f.endpoint)
            table.insert(output, "[!]   Issue: " .. f.type)
            table.insert(output, "[!]   Severity: " .. f.severity)
            table.insert(output, "")
        end
        table.insert(output, "[!] Introspection exposes full API schema to attackers")
        return stdnse.format_output(true, output)
    end

    return nil
end
