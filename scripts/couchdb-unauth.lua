local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks if CouchDB instance allows unauthenticated access and
exposes database information, configuration, or admin endpoints.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 5984 or port.service == "couchdb")
end

action = function(host, port)
    local output = {}
    local issues = {}

    local endpoints = {
        {path = "/", name = "Root"},
        {path = "/_all_dbs", name = "Database List"},
        {path = "/_config", name = "Configuration"},
        {path = "/_membership", name = "Membership"},
        {path = "/_users", name = "Users Database"},
    }

    table.insert(output, "CouchDB Unauthenticated Access Check:")

    for _, ep in ipairs(endpoints) do
        local response = http.get(host, port, ep.path)

        if response then
            if response.status == 200 then
                table.insert(output, "  " .. ep.name .. " (" .. ep.path .. "): ACCESSIBLE")

                if ep.path == "/" and response.body then
                    local version = response.body:match('"version"%s*:%s*"([^"]+)"')
                    if version then
                        table.insert(output, "    Version: " .. version)
                    end
                    local uuid = response.body:match('"uuid"%s*:%s*"([^"]+)"')
                    if uuid then
                        table.insert(output, "    UUID: " .. uuid)
                    end
                end

                if ep.path == "/_all_dbs" then
                    table.insert(issues, "CRITICAL: Database listing accessible without auth")
                end

                if ep.path == "/_config" then
                    table.insert(issues, "CRITICAL: Server configuration accessible (may expose credentials)")
                end
            elseif response.status == 401 then
                table.insert(output, "  " .. ep.name .. ": Authentication required")
            elseif response.status == 403 then
                table.insert(output, "  " .. ep.name .. ": Forbidden")
            end
        end
    end

    if #issues > 0 then
        table.insert(output, "\nSecurity Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Set a strong admin password")
    table.insert(output, "  - Enable CouchDB authentication")
    table.insert(output, "  - Restrict network access to trusted hosts")

    return stdnse.format_output(true, output)
end
