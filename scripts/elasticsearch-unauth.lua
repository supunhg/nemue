local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks if Elasticsearch cluster information is accessible without
authentication, including cluster health, nodes, and indices.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 9200 or port.service == "wap-wsp")
end

action = function(host, port)
    local output = {}
    local issues = {}

    local endpoints = {
        {path = "/", name = "Root"},
        {path = "/_cluster/health", name = "Cluster Health"},
        {path = "/_nodes", name = "Nodes"},
        {path = "/_cat/indices", name = "Indices"},
        {path = "/_cat/shards", name = "Shards"},
    }

    table.insert(output, "Elasticsearch Unauthenticated Access Check:")

    for _, ep in ipairs(endpoints) do
        local response = http.get(host, port, ep.path)

        if response and response.status == 200 then
            table.insert(output, "  " .. ep.name .. " (" .. ep.path .. "): ACCESSIBLE")

            if ep.path == "/" and response.body then
                local version = response.body:match('"version"%s*:%s*{[^}]*"number"%s*:%s*"([^"]+)"')
                if version then
                    table.insert(output, "    Version: " .. version)
                end
                local cluster = response.body:match('"cluster_name"%s*:%s*"([^"]+)"')
                if cluster then
                    table.insert(output, "    Cluster: " .. cluster)
                end
            end

            if ep.path == "/_cluster/health" and response.body then
                local status = response.body:match('"status"%s*:%s*"([^"]+)"')
                if status then
                    table.insert(output, "    Health: " .. status)
                end
            end

            if ep.path == "/_cat/indices" then
                table.insert(issues, "CRITICAL: Index listing accessible without auth")
            end
        elseif response and response.status == 401 then
            table.insert(output, "  " .. ep.name .. ": Authentication required")
        end
    end

    if #issues > 0 then
        table.insert(output, "\nSecurity Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Enable X-Pack security")
    table.insert(output, "  - Require authentication for all endpoints")
    table.insert(output, "  - Restrict network access to Elasticsearch")

    return stdnse.format_output(true, output)
end
