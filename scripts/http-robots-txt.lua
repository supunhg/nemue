-- HTTP robots.txt Parser
-- Parses robots.txt for hidden paths and directories

local http = require("http")
local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Fetches and parses robots.txt to discover hidden paths,
disallowed directories, and sitemap references.
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
    local disallowed = {}
    local sitemaps = {}

    local response = http.get(host, port, "/robots.txt")

    if not response or response.status ~= 200 then
        return stdnse.format_output(true, "No robots.txt found (HTTP " ..
            (response and response.status or "no response") .. ")")
    end

    local body = response.body or ""

    for line in body:gmatch("[^\r\n]+") do
        local path = line:match("^%s*[Dd]isallow:%s*(.+)%s*$")
        if path and path ~= "" then
            table.insert(disallowed, path)
        end

        local sitemap = line:match("^%s*[Ss]itemap:%s*(.+)%s*$")
        if sitemap then
            table.insert(sitemaps, sitemap)
        end
    end

    if #disallowed > 0 then
        table.insert(output, "Disallowed Paths (" .. #disallowed .. "):")
        for _, path in ipairs(disallowed) do
            table.insert(output, "  " .. path)
        end
    end

    if #sitemaps > 0 then
        table.insert(output, "\nSitemaps Found (" .. #sitemaps .. "):")
        for _, url in ipairs(sitemaps) do
            table.insert(output, "  " .. url)
        end
    end

    if #disallowed == 0 and #sitemaps == 0 then
        table.insert(output, "robots.txt exists but contains no directives")
    end

    table.insert(output, "\n[!] Disallowed paths may contain sensitive content")

    return stdnse.format_output(true, output)
end
