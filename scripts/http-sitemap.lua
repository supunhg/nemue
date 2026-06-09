-- HTTP Sitemap Parser
-- Parses sitemap.xml for endpoints and URLs

local http = require("http")
local nmap = require("nmap")
local stdnse = require("stdnse")
local string = require("string")
local table = require("table")

description = [[
Fetches and parses sitemap.xml to discover website endpoints,
pages, and URL patterns.
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

local function parse_sitemap(body)
    local urls = {}
    for loc in body:gmatch("<loc>%s*(.-)%s*</loc>") do
        table.insert(urls, loc)
    end
    return urls
end

action = function(host, port)
    local output = {}
    local all_urls = {}
    local sitemap_paths = {"/sitemap.xml", "/sitemap_index.xml", "/sitemap/"}

    for _, path in ipairs(sitemap_paths) do
        local response = http.get(host, port, path)

        if response and response.status == 200 and response.body then
            table.insert(output, "Found: " .. path)

            local urls = parse_sitemap(response.body)
            for _, url in ipairs(urls) do
                table.insert(all_urls, url)
            end

            if response.body:find("sitemap") and response.body:find("<loc>") then
                for nested in response.body:gmatch("<sitemap>.-<loc>(.-)</loc>.-</sitemap>") do
                    table.insert(sitemap_paths, nested)
                end
            end
        end
    end

    if #all_urls > 0 then
        table.insert(output, "\nDiscovered URLs (" .. #all_urls .. "):")
        local shown = math.min(#all_urls, 50)
        for i = 1, shown do
            table.insert(output, "  " .. all_urls[i])
        end
        if #all_urls > shown then
            table.insert(output, "  ... and " .. (#all_urls - shown) .. " more")
        end
    else
        table.insert(output, "No sitemap found")
    end

    return stdnse.format_output(true, output)
end
