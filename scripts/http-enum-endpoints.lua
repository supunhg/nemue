-- HTTP Endpoint Enumeration
-- Discovers web application endpoints and pages

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates web application endpoints by testing common paths,
analyzing sitemaps, and crawling for hidden resources.
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

    local endpoints = {
        "/robots.txt", "/sitemap.xml", "/sitemap_index.xml",
        "/.well-known/security.txt", "/.well-known/change-password",
        "/humans.txt", "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/favicon.ico", "/apple-touch-icon.png",
        "/manifest.json", "/browserconfig.xml",
        "/admin", "/login", "/register", "/signup",
        "/dashboard", "/panel", "/console",
        "/profile", "/account", "/settings",
        "/search", "/help", "/about", "/contact",
        "/docs", "/documentation", "/wiki",
        "/status", "/health", "/info", "/version",
        "/debug", "/test", "/dev", "/staging",
    }

    for _, path in ipairs(endpoints) do
        local r = http.get(host.ip, port, path)
        if r and r.status and r.status ~= 404 and r.status ~= 0 then
            if r.status == 200 or r.status == 301 or r.status == 302 or
               r.status == 403 or r.status == 401 then
                table.insert(findings, path .. " - HTTP " .. r.status)
            end
        end
    end

    local sitemap_r = http.get(host.ip, port, "/sitemap.xml")
    if sitemap_r and sitemap_r.body then
        for loc in sitemap_r.body:gmatch("<loc>([^<]+)</loc>") do
            local path = loc:match("https?://[^/]+(/.*)")
            if path then
                table.insert(findings, path .. " (from sitemap.xml)")
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "Endpoints Discovered:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] INFO: " .. #findings .. " endpoints discovered")
        return stdnse.format_output(true, output)
    end

    return nil
end
