-- Virtual Host Enumeration
-- Discovers virtual hosts on web servers

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Enumerates virtual hosts by testing common hostnames
against the web server using Host header manipulation.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

action = function(host, port)
    local output = {}
    local vhosts = {}

    local base_domain = host.name or ""
    local domain_parts = {}
    for part in base_domain:gmatch("[^%.]+") do
        table.insert(domain_parts, part)
    end

    local prefixes = {
        "www", "mail", "ftp", "admin", "test", "dev", "staging",
        "api", "app", "beta", "demo", "portal", "login", "sso",
        "cdn", "static", "media", "images", "docs", "wiki",
        "blog", "shop", "store", "support", "help", "status",
        "monitor", "grafana", "jenkins", "gitlab", "jira", "confluence"
    }

    local base = ""
    if #domain_parts >= 2 then
        base = domain_parts[#domain_parts - 1] .. "." .. domain_parts[#domain_parts]
    end

    table.insert(output, "Virtual Host Enumeration")
    table.insert(output, "Base domain: " .. base_domain)
    table.insert(output, "")

    for _, prefix in ipairs(prefixes) do
        local vhost = prefix .. "." .. base

        if vhost ~= base_domain then
            local options = {
                header = {["Host"] = vhost}
            }

            local response = http.get(host.ip, port, "/", options)

            if response and response.status == 200 then
                local body = response.body or ""
                if not body:find("404") and not body:find("Not Found") then
                    table.insert(vhosts, vhost)
                    table.insert(output, "[+] Virtual host found: " .. vhost)
                end
            end
        end
    end

    table.insert(output, "")
    table.insert(output, "Virtual hosts discovered: " .. #vhosts)

    if #vhosts > 0 then
        table.insert(output, "[!] Additional attack surface discovered")
    end

    return stdnse.format_output(true, output)
end
