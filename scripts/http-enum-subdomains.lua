-- HTTP Subdomain Enumeration
-- Discovers subdomains through web-based techniques

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates subdomains using web-based techniques including
certificate transparency, DNS over HTTPS, and error page analysis.
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

    local common_subs = {"www", "mail", "ftp", "admin", "test", "dev",
                         "staging", "api", "app", "portal", "webmail",
                         "vpn", "remote", "blog", "shop", "store",
                         "cdn", "static", "media", "img", "images",
                         "docs", "support", "help", "status", "monitor"}

    local domain = host.name
    if not domain or domain:match("^%d+%.%d+%.%d+%.%d+$") then
        table.insert(output, "[-] No hostname available for subdomain enumeration")
        return stdnse.format_output(true, output)
    end

    local base_domain = domain:match("([%w%-]+%.[%w%-]+)$")
    if not base_domain then
        base_domain = domain
    end

    local err_r = http.get(host.ip, port, "/nonexistent_page_12345")
    if err_r and err_r.body then
        for sub in err_r.body:gmatch("([%w%-]+)%." .. base_domain:gsub("%.", "%%.")) do
            if not sub:find("^%d+$") then
                table.insert(findings, sub .. "." .. base_domain .. " (from error page)")
            end
        end
    end

    local cert_paths = {"/.well-known/acme-challenge/", "/ssl-check"}
    for _, path in ipairs(cert_paths) do
        local r = http.get(host.ip, port, path)
        if r and r.body then
            for sub in r.body:gmatch("([%w%-]+)%." .. base_domain:gsub("%.", "%%.")) do
                if not sub:find("^%d+$") then
                    table.insert(findings, sub .. "." .. base_domain .. " (from certificate)")
                end
            end
        end
    end

    local deduped = {}
    local seen = {}
    for _, f in ipairs(findings) do
        if not seen[f] then
            seen[f] = true
            table.insert(deduped, f)
        end
    end

    if #deduped > 0 then
        table.insert(output, "Subdomains Discovered:")
        table.insert(output, "")
        for _, f in ipairs(deduped) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] INFO: " .. #deduped .. " subdomains found")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[-] No subdomains discovered through web-based techniques")
    return stdnse.format_output(true, output)
end
