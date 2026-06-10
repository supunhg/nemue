-- HTTP Parameter Enumeration
-- Discovers URL parameters used by web applications

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates URL parameters by analyzing forms, JavaScript files,
and testing common parameter names on discovered endpoints.
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

    local response = http.get(host.ip, port, "/")
    if not response or not response.body then
        return "No HTTP response received"
    end

    local body = response.body

    for input in body:gmatch("<input[^>]+name=[\"']([^\"']+)[\"']") do
        table.insert(findings, "Form input: " .. input)
    end

    for param in body:gmatch("[%?&]([%w_]+)=") do
        table.insert(findings, "URL parameter: " .. param)
    end

    local common_params = {"id", "page", "search", "q", "query", "sort", "order",
                           "limit", "offset", "filter", "type", "action", "cmd",
                           "file", "path", "dir", "name", "user", "email", "token"}

    local test_paths = {"/search", "/api/search", "/list"}
    for _, path in ipairs(test_paths) do
        for _, param in ipairs(common_params) do
            local url = path .. "?" .. param .. "=test"
            local r = http.get(host.ip, port, url)
            if r and r.status == 200 and r.body and
               not r.body:find("error") and not r.body:find("not found") then
                table.insert(findings, "Active parameter: " .. param .. " at " .. path)
            end
        end
    end

    local js_files = {}
    for src in body:gmatch('src=["\']([^"\']-%.js)["\']') do
        table.insert(js_files, src)
    end

    for _, js in ipairs(js_files) do
        local js_r = http.get(host.ip, port, js)
        if js_r and js_r.body then
            for param in js_r.body:gmatch('["\']([%w_]+)["\']:%s*["\']?[%w]') do
                if #param > 2 and #param < 30 then
                    table.insert(findings, "JS parameter: " .. param .. " (from " .. js .. ")")
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
        table.insert(output, "Parameters Discovered:")
        table.insert(output, "")
        for _, f in ipairs(deduped) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] INFO: " .. #deduped .. " parameters found")
        return stdnse.format_output(true, output)
    end

    return nil
end
