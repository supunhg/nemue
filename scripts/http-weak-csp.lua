-- Weak Content-Security-Policy Detection
-- Analyzes CSP for weaknesses and misconfigurations

local http = require("http")
local stdnse = require("stdnse")

description = [[
Analyzes Content-Security-Policy header for weaknesses including
unsafe-inline, unsafe-eval, wildcard sources, and other misconfigurations.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Weak CSP Analysis")
    table.insert(output, "")

    local csp = response.header and response.header["content-security-policy"]
    if not csp then
        table.insert(output, "[-] No CSP header present")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[i] CSP: " .. csp)
    table.insert(output, "")

    local warnings = {}

    if csp:find("'unsafe%-inline'") then
        table.insert(warnings, "unsafe-inline allows inline scripts/styles (XSS risk)")
    end

    if csp:find("'unsafe%-eval'") then
        table.insert(warnings, "unsafe-eval allows eval() (code injection risk)")
    end

    if csp:find("%*") and not csp:find("%*%.") then
        table.insert(warnings, "Wildcard source '*' allows any domain")
    end

    if csp:find("data:") then
        table.insert(warnings, "data: URIs allowed (can bypass CSP)")
    end

    if csp:find("https://*") or csp:find("https://%*") then
        table.insert(warnings, "Wildcard HTTPS allows any HTTPS source")
    end

    if not csp:find("default%-src") then
        table.insert(warnings, "Missing default-src directive")
    end

    if not csp:find("script%-src") then
        table.insert(warnings, "Missing script-src directive")
    end

    if csp:find("nonce%-") and #csp:match("nonce%-([%w+/=]+)") < 16 then
        table.insert(warnings, "CSP nonce is too short (should be 128+ bits)")
    end

    if #warnings > 0 then
        table.insert(output, "CSP Weaknesses Found:")
        for _, w in ipairs(warnings) do
            table.insert(output, "[!] " .. w)
        end
        table.insert(output, "")
        table.insert(output, "[!] MEDIUM: Weak CSP provides limited XSS protection")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[+] CSP appears reasonably configured")
    return stdnse.format_output(true, output)
end
