-- HTTP .well-known Directory Check
-- Checks .well-known directory for known configuration files

local http = require("http")
local nmap = require("nmap")
local stdnse = require("stdnse")
local table = require("table")

description = [[
Checks for common files in the .well-known directory including
security.txt, openId-configuration, and other standard paths.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default", "discovery"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

action = function(host, port)
    local output = {}
    local found = 0

    local well_known_paths = {
        "/.well-known/security.txt",
        "/.well-known/openid-configuration",
        "/.well-known/host-meta",
        "/.well-known/assetlinks.json",
        "/.well-known/apple-app-site-association",
        "/.well-known/change-password",
        "/.well-known/oauth-authorization-server",
        "/.well-known/webfinger",
        "/.well-known/mta-sts.txt",
        "/.well-known/dnt-policy.txt",
        "/.well-known/robots.txt",
        "/.well-known/humans.txt"
    }

    for _, path in ipairs(well_known_paths) do
        local response = http.get(host, port, path)

        if response and response.status == 200 then
            found = found + 1
            table.insert(output, "[+] " .. path .. " (HTTP 200)")

            if path:find("security.txt") and response.body then
                local contact = response.body:match("[Cc]onact:%s*(.+)")
                if contact then
                    table.insert(output, "    Contact: " .. contact:sub(1, 80))
                end
            end

            if path:find("openid") and response.body then
                table.insert(output, "    OpenID configuration detected")
            end
        end
    end

    if found > 0 then
        table.insert(output, "\nFound " .. found .. " well-known resources")
    else
        table.insert(output, "No .well-known resources found")
    end

    return stdnse.format_output(true, output)
end
