local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Tests Kubernetes API server exposure and checks for unauthenticated
access to sensitive API endpoints.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 6443 or port.number == 8080 or port.number == 8443 or
            port.service == "https")
end

action = function(host, port)
    local output = {}
    local issues = {}

    local endpoints = {
        {path = "/api", name = "API Root"},
        {path = "/api/v1", name = "API v1"},
        {path = "/apis", name = "API Groups"},
        {path = "/version", name = "Version"},
        {path = "/healthz", name = "Health Check"},
        {path = "/metrics", name = "Metrics"},
    }

    for _, ep in ipairs(endpoints) do
        local response = http.get(host, port, ep.path)

        if response then
            if response.status == 200 then
                table.insert(output, ep.name .. " (" .. ep.path .. "): Accessible")

                if ep.path == "/version" and response.body then
                    local version = response.body:match('"gitVersion"%s*:%s*"([^"]+)"')
                    if version then
                        table.insert(output, "  Kubernetes Version: " .. version)
                    end
                end

                if ep.path == "/api/v1" or ep.path == "/apis" then
                    table.insert(issues, "API endpoint accessible: " .. ep.path)
                end

                if ep.path == "/metrics" then
                    table.insert(issues, "Metrics endpoint exposed (information disclosure)")
                end
            elseif response.status == 401 then
                table.insert(output, ep.name .. ": Authentication required")
            elseif response.status == 403 then
                table.insert(output, ep.name .. ": Forbidden")
            end
        end
    end

    if #issues > 0 then
        table.insert(output, "\nFindings:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Enable RBAC authorization")
    table.insert(output, "  - Use service account tokens")
    table.insert(output, "  - Restrict anonymous access")
    table.insert(output, "  - Use network policies to limit API access")

    return stdnse.format_output(true, output)
end
