local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks if Docker API is exposed and accessible without authentication.
Tests for container listing and system information access.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 2375 or port.number == 2376 or port.service == "docker")
end

action = function(host, port)
    local output = {}
    local issues = {}

    local endpoints = {
        {path = "/version", name = "Version"},
        {path = "/info", name = "System Info"},
        {path = "/containers/json", name = "Container List"},
        {path = "/images/json", name = "Image List"},
    }

    for _, ep in ipairs(endpoints) do
        local response = http.get(host, port, ep.path)

        if response and response.status == 200 then
            table.insert(output, ep.name .. " endpoint: ACCESSIBLE")

            if ep.path == "/version" and response.body then
                local version = response.body:match('"Version"%s*:%s*"([^"]+)"')
                if version then
                    table.insert(output, "  Docker Version: " .. version)
                end
                local api = response.body:match('"ApiVersion"%s*:%s*"([^"]+)"')
                if api then
                    table.insert(output, "  API Version: " .. api)
                end
            end

            if ep.path == "/info" and response.body then
                local containers = response.body:match('"Containers"%s*:%s*(%d+)')
                if containers then
                    table.insert(output, "  Containers: " .. containers)
                end
            end

            if ep.path == "/containers/json" then
                table.insert(issues, "CRITICAL: Container listing accessible without auth")
            end
        elseif response and response.status == 401 then
            table.insert(output, ep.name .. " endpoint: Authentication required")
        elseif response and response.status == 403 then
            table.insert(output, ep.name .. " endpoint: Forbidden")
        end
    end

    if #issues > 0 then
        table.insert(output, "\nSecurity Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Use TLS client certificate authentication")
    table.insert(output, "  - Bind Docker daemon to unix socket only")
    table.insert(output, "  - Never expose Docker API on 0.0.0.0")

    return stdnse.format_output(true, output)
end
