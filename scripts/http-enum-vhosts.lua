-- HTTP Virtual Host Enumeration
-- Discovers virtual hosts on the web server

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates virtual hosts by sending different Host headers and
analyzing responses to identify hosted domains.
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

    local base_domain = host.name
    if not base_domain or base_domain:match("^%d+%.%d+%.%d+%.%d+$") then
        table.insert(output, "[-] No hostname available for vhost enumeration")
        return stdnse.format_output(true, output)
    end

    local base_r = http.get(host.ip, port, "/")
    local base_title = ""
    if base_r and base_r.body then
        base_title = base_r.body:match("<title>([^<]+)</title>") or ""
    end

    local vhosts = {
        "www." .. base_domain,
        "mail." .. base_domain,
        "admin." .. base_domain,
        "test." .. base_domain,
        "dev." .. base_domain,
        "staging." .. base_domain,
        "api." .. base_domain,
        "app." .. base_domain,
        "portal." .. base_domain,
        "old." .. base_domain,
        "backup." .. base_domain,
    }

    for _, vhost in ipairs(vhosts) do
        local headers = {["Host"] = vhost}
        local r = http.get(host.ip, port, "/", headers)
        if r and r.status == 200 and r.body then
            local title = r.body:match("<title>([^<]+)</title>") or ""
            if title ~= base_title and #title > 0 then
                table.insert(findings, vhost .. " (Title: " .. title .. ")")
            elseif r.status ~= (base_r and base_r.status or 0) then
                table.insert(findings, vhost .. " (HTTP " .. r.status .. ")")
            end
        elseif r and r.status == 301 or r and r.status == 302 then
            local location = r.header and r.header["location"]
            if location and not location:find(base_domain) then
                table.insert(findings, vhost .. " -> " .. location)
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "Virtual Hosts Discovered:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] INFO: " .. #findings .. " virtual hosts found")
        return stdnse.format_output(true, output)
    end

    return nil
end
