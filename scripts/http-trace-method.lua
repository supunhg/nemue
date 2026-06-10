local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Tests if HTTP TRACE method is enabled, which can lead to
Cross-Site Tracing (XST) attacks exposing cookie data.
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

    local options = {
        header = {
            ["X-Test-Header"] = "trace-test-value",
        },
    }

    local response = http.generic_request(host, port, "TRACE", "/", options)

    if not response then
        table.insert(output, "TRACE request failed or blocked")
        return stdnse.format_output(true, output)
    end

    if response.status == 200 then
        table.insert(issues, "CRITICAL: TRACE method is enabled")

        if response.body and response.body:find("X%-Test%-Header") then
            table.insert(issues, "Headers reflected in TRACE response (XST vulnerability)")
        end

        if response.body and response.body:find("Cookie") then
            table.insert(issues, "Cookie data may be exposed via TRACE")
        end
    elseif response.status == 403 then
        table.insert(output, "TRACE method is disabled (403 Forbidden)")
    elseif response.status == 405 then
        table.insert(output, "TRACE method is not allowed (405)")
    else
        table.insert(output, "TRACE returned status: " .. response.status)
    end

    if #issues > 0 then
        table.insert(output, "\nTRACE Method Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
