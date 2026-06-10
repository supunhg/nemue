-- HTTP API Enumeration
-- Discovers API endpoints and documentation

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates API endpoints by checking common API paths, documentation
endpoints, and analyzing robots.txt and sitemap files.
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

    local api_paths = {
        {"/api", "API root"},
        {"/api/v1", "API v1"},
        {"/api/v2", "API v2"},
        {"/api/v3", "API v3"},
        {"/api/swagger.json", "Swagger JSON"},
        {"/swagger.json", "Swagger JSON"},
        {"/swagger-ui.html", "Swagger UI"},
        {"/swagger-ui/", "Swagger UI"},
        {"/api-docs", "API documentation"},
        {"/openapi.json", "OpenAPI spec"},
        {"/openapi.yaml", "OpenAPI spec"},
        {"/api/docs", "API docs"},
        {"/api/explorer", "API explorer"},
        {"/graphql", "GraphQL endpoint"},
        {"/graphiql", "GraphiQL interface"},
    }

    for _, check in ipairs(api_paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status and r.status ~= 404 then
            table.insert(findings, check[1] .. " (" .. check[2] .. ") - HTTP " .. r.status)
        end
    end

    local robots_r = http.get(host.ip, port, "/robots.txt")
    if robots_r and robots_r.body then
        for line in robots_r.body:gmatch("[^\r\n]+") do
            local path = line:match("Allow:%s*(.+)")
            if path and (path:find("/api") or path:find("/v%d")) then
                table.insert(findings, path .. " (from robots.txt)")
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "API Endpoints Discovered:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] INFO: API endpoints discovered for further testing")
        return stdnse.format_output(true, output)
    end

    return nil
end
