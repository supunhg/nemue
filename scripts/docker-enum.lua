-- Docker Enumeration
-- Enumerates Docker daemon information and containers

local http = require("http")
local json = require("json")
local stdnse = require("stdnse")

description = [[
Connects to Docker daemon API to enumerate containers,
images, volumes, and configuration information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 2375 or port.number == 2376 or
            port.service == "docker")
end

action = function(host, port)
    local output = {}

    table.insert(output, "Docker Daemon Enumeration")
    table.insert(output, "Target: " .. host.ip .. ":" .. port.number)
    table.insert(output, "")

    local endpoints = {
        {"/version", "Version Info"},
        {"/info", "System Info"},
        {"/containers/json", "Containers"},
        {"/images/json", "Images"},
        {"/volumes", "Volumes"},
        {"/networks", "Networks"}
    }

    local accessible = false

    for _, endpoint in ipairs(endpoints) do
        local response = http.get(host.ip, port, endpoint[1])

        if response and response.status == 200 then
            accessible = true
            table.insert(output, "[+] " .. endpoint[2] .. " endpoint accessible")

            local body = response.body or ""

            if endpoint[1] == "/version" then
                local version = body:match('"Version":"([^"]*)"')
                if version then
                    table.insert(output, "    Docker Version: " .. version)
                end

                local api = body:match('"ApiVersion":"([^"]*)"')
                if api then
                    table.insert(output, "    API Version: " .. api)
                end
            elseif endpoint[1] == "/containers/json" then
                local count = 0
                for _ in body:gmatch('"Id"') do
                    count = count + 1
                end
                table.insert(output, "    Running Containers: " .. count)
            elseif endpoint[1] == "/images/json" then
                local count = 0
                for _ in body:gmatch('"Id"') do
                    count = count + 1
                end
                table.insert(output, "    Images: " .. count)
            end
        end
    end

    table.insert(output, "")

    if accessible then
        table.insert(output, "[!] CRITICAL: Docker API accessible without authentication")
        table.insert(output, "[!] Attackers can:")
        table.insert(output, "    - List and inspect all containers")
        table.insert(output, "    - Create privileged containers for host escape")
        table.insert(output, "    - Mount host filesystem")
        table.insert(output, "    - Execute commands in running containers")
        table.insert(output, "")
        table.insert(output, "[!] Recommendation: Enable TLS authentication for Docker API")
    else
        table.insert(output, "[+] Docker API not accessible or requires authentication")
    end

    return stdnse.format_output(true, output)
end
