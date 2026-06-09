-- HTTP Security Headers Check
-- Checks for important security headers

local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks for critical HTTP security headers including
X-Content-Type-Options, X-XSS-Protection, and Strict-Transport-Security.
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
        local xcto = response.header["x-content-type-options"]
        local xxss = response.header["x-xss-protection"]
        local hsts = response.header["strict-transport-security"]
        local xfo = response.header["x-frame-options"]
        local csp = response.header["content-security-policy"]

        if not xcto then
            table.insert(issues, "Missing X-Content-Type-Options header")
        elseif xcto:lower() ~= "nosniff" then
            table.insert(issues, "Weak X-Content-Type-Options: " .. xcto)
        end

        if not xxss then
            table.insert(issues, "Missing X-XSS-Protection header")
        end

        if port.service == "https" or port.number == 443 then
            if not hsts then
                table.insert(issues, "Missing Strict-Transport-Security header")
            end
        end

        if not xfo then
            table.insert(issues, "Missing X-Frame-Options header")
        end

        if not csp then
            table.insert(issues, "Missing Content-Security-Policy header")
        end
    end

    if #issues > 0 then
        table.insert(output, "Security Header Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  [!] " .. issue)
        end
    else
        table.insert(output, "All security headers present")
    end

    return stdnse.format_output(true, output)
end
