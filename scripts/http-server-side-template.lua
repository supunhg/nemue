-- Server-Side Template Injection Detection (SSTI)
-- Checks for template injection vulnerabilities
-- @output
-- 80/tcp open  http
-- | http-server-side-template:
-- |   WARNING: SSTI vulnerability detected
-- |     Template engine responding to injection
-- |_    Engine: Jinja2/Twig/Smarty

description = [[
Detects Server-Side Template Injection (SSTI) vulnerabilities.
Tests multiple template syntaxes including Jinja2, Twig, Smarty,
FreeMarker, and Velocity.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "http"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local vulns = {}

    local test_paths = {
        "/", "/search", "/query", "/page", "/render",
        "/template", "/preview", "/test", "/api"
    }

    local ssti_payloads = {
        {payload = "{{7*7}}", result = "49", engine = "Jinja2/Twig"},
        {payload = "${7*7}", result = "49", engine = "FreeMarker/Velocity"},
        {payload = "<%= 7*7 %>", result = "49", engine = "ERB"},
        {payload = "#{7*7}", result = "49", engine = "Slim/Ruby"},
        {payload = "*{7*7}", result = "49", engine = "Thymeleaf"},
        {payload = "{{config}}", result = "SECRET", engine = "Jinja2"},
        {payload = "{{self.__class__.__mro__}}", result = "object", engine = "Jinja2"},
    }

    for _, path in ipairs(test_paths) do
        for _, test in ipairs(ssti_payloads) do
            local encoded = http.escape(test.payload)
            local test_url = path .. "?q=" .. encoded
            local response = http.get(host, port, test_url)

            if response and response.status == 200 and response.body then
                if response.body:find(test.result) then
                    table.insert(vulns, "SSTI detected on " .. path .. " (" .. test.engine .. ")")
                    break
                end
            end

            local options = {
                header = {
                    ["Content-Type"] = "application/x-www-form-urlencoded"
                }
            }
            local post_data = "input=" .. encoded
            local post_response = http.post(host, port, path, options, nil, post_data)
            if post_response and post_response.status == 200 and post_response.body then
                if post_response.body:find(test.result) then
                    table.insert(vulns, "SSTI via POST on " .. path .. " (" .. test.engine .. ")")
                    break
                end
            end
        end
    end

    if #vulns > 0 then
        local result = "WARNING: SSTI vulnerability detected\n"
        result = result .. "  Template engine responding to injection\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "No SSTI vulnerabilities detected"
end
