-- HTTP Clickjacking Protection Check
-- Checks for X-Frame-Options and CSP frame-ancestors

local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks if the target has clickjacking protection by examining
X-Frame-Options and Content-Security-Policy frame-ancestors headers.
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

    local response = http.get(host, port, "/")

    if response and response.header then
        local xfo = response.header["x-frame-options"]
        local csp = response.header["content-security-policy"]

        if not xfo then
            table.insert(issues, "Missing X-Frame-Options header")
        else
            local xfo_upper = xfo:upper()
            if xfo_upper ~= "DENY" and xfo_upper ~= "SAMEORIGIN" then
                table.insert(issues, "Weak X-Frame-Options value: " .. xfo)
            end
        end

        local has_frame_ancestors = false
        if csp then
            if csp:lower():find("frame%-ancestors") then
                has_frame_ancestors = true
            end
        end

        if not has_frame_ancestors then
            table.insert(issues, "Missing CSP frame-ancestors directive")
        end

        if not xfo and not has_frame_ancestors then
            table.insert(issues, "CRITICAL: No clickjacking protection found")
        end
    end

    if #issues > 0 then
        table.insert(output, "Clickjacking Protection Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    else
        table.insert(output, "Clickjacking protection is properly configured")
    end

    return stdnse.format_output(true, output)
end
