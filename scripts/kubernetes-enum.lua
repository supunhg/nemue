-- Kubernetes Enumeration
-- Enumerates Kubernetes API server information

local http = require("http")
local json = require("json")
local stdnse = require("stdnse")

description = [[
Connects to Kubernetes API server to enumerate cluster
information, namespaces, pods, and services.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 6443 or port.number == 8080 or
            port.number == 8443 or port.service == "kubernetes")
end

action = function(host, port)
    local output = {}

    table.insert(output, "Kubernetes API Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":" .. port.number)
    table.insert(output, "")

    local endpoints = {
        {"/api", "API Root"},
        {"/api/v1", "API v1"},
        {"/apis", "API Groups"},
        {"/api/v1/namespaces", "Namespaces"},
        {"/api/v1/pods", "Pods"},
        {"/api/v1/services", "Services"},
        {"/api/v1/nodes", "Nodes"},
        {"/api/v1/secrets", "Secrets"},
        {"/api/v1/configmaps", "ConfigMaps"},
        {"/version", "Version"}
    }

    local accessible = false

    for _, endpoint in ipairs(endpoints) do
        local response = http.get(host.ip, port, endpoint[1])

        if response and response.status == 200 then
            accessible = true
            table.insert(output, "[+] " .. endpoint[2] .. " endpoint accessible")

            local body = response.body or ""

            if endpoint[1] == "/version" then
                local major = body:match('"major":"([^"]*)"')
                local minor = body:match('"minor":"([^"]*)"')
                if major and minor then
                    table.insert(output, "    Kubernetes Version: " .. major .. "." .. minor)
                end

                local platform = body:match('"platform":"([^"]*)"')
                if platform then
                    table.insert(output, "    Platform: " .. platform)
                end
            elseif endpoint[1] == "/api/v1/namespaces" then
                local count = 0
                for _ in body:gmatch('"name"') do
                    count = count + 1
                end
                table.insert(output, "    Namespaces: " .. count)
            elseif endpoint[1] == "/api/v1/pods" then
                local count = 0
                for _ in body:gmatch('"name"') do
                    count = count + 1
                end
                table.insert(output, "    Pods: " .. count)
            elseif endpoint[1] == "/api/v1/nodes" then
                local count = 0
                for _ in body:gmatch('"name"') do
                    count = count + 1
                end
                table.insert(output, "    Nodes: " .. count)
            end
        end
    end

    table.insert(output, "")

    if accessible then
        table.insert(output, "[!] CRITICAL: Kubernetes API accessible without authentication")
        table.insert(output, "[!] Attackers can:")
        table.insert(output, "    - List all cluster resources")
        table.insert(output, "    - Access secrets and configmaps")
        table.insert(output, "    - Create/modify/delete pods")
        table.insert(output, "    - Escalate privileges via service accounts")
        table.insert(output, "")
        table.insert(output, "[!] Recommendation: Enable RBAC and authentication")
    else
        table.insert(output, "[+] Kubernetes API not accessible or requires authentication")
    end

    return stdnse.format_output(true, output)
end
