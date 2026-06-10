-- Mixed Content Detection
-- Detects HTTP resources loaded over HTTPS pages

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects mixed content issues where HTTPS pages load resources
over insecure HTTP connections, potentially allowing MitM attacks.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "https" or port.number == 443 or port.number == 8443)
end

action = function(host, port)
    local output = {}
    local findings = {}

    local response = http.get(host.ip, port, "/")
    if not response or not response.body then
        return "No HTTP response received"
    end

    local body = response.body

    local http_refs = {
        {"http://[^\"' >]+%.js", "JavaScript"},
        {"http://[^\"' >]+%.css", "Stylesheet"},
        {"http://[^\"' >]+%.png", "Image"},
        {"http://[^\"' >]+%.jpg", "Image"},
        {"http://[^\"' >]+%.gif", "Image"},
        {"http://[^\"' >]+%.svg", "Image"},
        {"src=\"http://", "Resource src"},
        {"href=\"http://", "Resource href"},
        {"url%(%s*http://", "CSS url()"},
    }

    for _, pattern in ipairs(http_refs) do
        for match in body:gmatch(pattern[1]) do
            if not match:find(host.ip) and not match:find(host.name or "") then
                table.insert(findings, pattern[2] .. ": " .. match:sub(1, 80))
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
        table.insert(output, "Mixed Content Issues Found:")
        table.insert(output, "")
        for _, f in ipairs(deduped) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] MEDIUM: Insecure HTTP resources on HTTPS page")
        return stdnse.format_output(true, output)
    end

    return nil
end
