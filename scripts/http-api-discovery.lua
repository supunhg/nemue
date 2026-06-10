-- HTTP REST API Discovery
-- Discovers REST API endpoints by probing common paths

local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Probes common REST API endpoint paths and reports which ones
return valid responses (200, 201, 301, 401, 403).
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

local api_paths = {
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/rest/v1", "/rest/v2",
    "/v1", "/v2", "/v3",
    "/api/swagger", "/api/docs", "/api/info",
    "/swagger.json", "/openapi.json", "/openapi.yaml",
    "/api/health", "/api/status", "/api/version",
    "/graphql", "/api/graphql",
    "/wp-json", "/wp-json/wp/v2",
    "/api/users", "/api/auth", "/api/login",
    "/api/config", "/api/settings",
}

action = function(host, port)
    local results = {}

    for _, path in ipairs(api_paths) do
        local response = http.get(host, port, path)
        if response then
            local code = response.status
            if code and (code == 200 or code == 201 or code == 301 or
                         code == 302 or code == 401 or code == 403) then
                local entry = path .. " [HTTP " .. code .. "]"
                if response.header and response.header["content-type"] then
                    entry = entry .. " (" .. response.header["content-type"] .. ")"
                end
                table.insert(results, entry)
            end
        end
    end

    if #results == 0 then
        return nil
    end

    return stdnse.format_output(true, results)
end
