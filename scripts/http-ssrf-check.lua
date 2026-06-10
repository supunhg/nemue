local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Tests for Server-Side Request Forgery (SSRF) by checking if the
server makes outbound requests to internal resources.
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

    local ssrf_params = {
        {param = "url", value = "http://127.0.0.1"},
        {param = "uri", value = "http://127.0.0.1"},
        {param = "path", value = "http://127.0.0.1"},
        {param = "src", value = "http://127.0.0.1"},
        {param = "dest", value = "http://127.0.0.1"},
        {param = "redirect", value = "http://127.0.0.1"},
        {param = "feed", value = "http://127.0.0.1"},
    }

    table.insert(output, "SSRF Parameter Check:")

    for _, test in ipairs(ssrf_params) do
        local path = "/?" .. test.param .. "=" .. test.value
        local response = http.get(host, port, path)

        if response and response.status == 200 then
            table.insert(output, "  Parameter '" .. test.param .. "' accepted request")
        end
    end

    local response = http.get(host, port, "/")
    if response and response.body then
        local body = response.body:lower()
        local internal_refs = {
            "127%.0%.0%.1",
            "192%.168%.",
            "10%.0%.0%.",
            "172%.16%.",
            "169%.254%.169%.254",
        }

        for _, ref in ipairs(internal_refs) do
            if body:find(ref) then
                table.insert(issues, "Internal IP reference found in response")
                break
            end
        end
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Validate and sanitize all URL parameters")
    table.insert(output, "  - Use allowlists for outbound requests")
    table.insert(output, "  - Block requests to internal IP ranges")

    if #issues > 0 then
        table.insert(output, "\nFindings:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
