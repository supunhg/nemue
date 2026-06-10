local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks for common XSS protections including X-XSS-Protection header,
Content-Security-Policy, and input reflection patterns.
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

    if not response or not response.header then
        return stdnse.format_output(false, "Could not retrieve HTTP response")
    end

    local xss_protect = response.header["x-xss-protection"]
    if not xss_protect then
        table.insert(issues, "Missing X-XSS-Protection header")
    elseif xss_protect == "0" then
        table.insert(issues, "X-XSS-Protection explicitly disabled")
    end

    local csp = response.header["content-security-policy"]
    if not csp then
        table.insert(issues, "Missing Content-Security-Policy header")
    else
        if not csp:lower():find("script%-src") then
            table.insert(issues, "CSP missing script-src directive")
        end
    end

    local xcto = response.header["x-content-type-options"]
    if not xcto or xcto:lower() ~= "nosniff" then
        table.insert(issues, "Missing or weak X-Content-Type-Options header")
    end

    local reflect_test = "?q=<script>alert(1)</script>"
    local r2 = http.get(host, port, reflect_test)
    if r2 and r2.body and r2.body:find("<script>alert%(1%)</script>") then
        table.insert(issues, "CRITICAL: Input reflected without sanitization")
    end

    if #issues > 0 then
        table.insert(output, "XSS Protection Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    else
        table.insert(output, "XSS protections appear properly configured")
    end

    return stdnse.format_output(true, output)
end
