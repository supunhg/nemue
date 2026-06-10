-- Weak HSTS Detection
-- Analyzes HSTS configuration for weaknesses

local http = require("http")
local stdnse = require("stdnse")

description = [[
Analyzes HTTP Strict Transport Security (HSTS) configuration for
weaknesses including short max-age, missing includeSubDomains,
and missing preload directive.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "https" or port.number == 443 or
            port.number == 8443)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Weak HSTS Analysis")
    table.insert(output, "")

    local hsts = response.header and response.header["strict-transport-security"]
    if not hsts then
        table.insert(output, "[-] No HSTS header present")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[i] HSTS: " .. hsts)
    table.insert(output, "")

    local warnings = {}

    local max_age = hsts:match("max%-age=(%d+)")
    if max_age then
        local age = tonumber(max_age)
        if age < 31536000 then
            table.insert(warnings, "max-age is " .. age .. " seconds (recommended: 31536000 / 1 year)")
        end
        if age < 86400 then
            table.insert(warnings, "max-age is less than 1 day - effectively disabled")
        end
    else
        table.insert(warnings, "Missing max-age directive")
    end

    if not hsts:find("includeSubDomains") then
        table.insert(warnings, "Missing includeSubDomains - subdomains not protected")
    end

    if not hsts:find("preload") then
        table.insert(warnings, "Missing preload directive - not eligible for HSTS preload list")
    end

    if #warnings > 0 then
        table.insert(output, "HSTS Weaknesses Found:")
        for _, w in ipairs(warnings) do
            table.insert(output, "[!] " .. w)
        end
        table.insert(output, "")
        table.insert(output, "[!] MEDIUM: Weak HSTS configuration")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "[+] HSTS configuration appears strong")
    return stdnse.format_output(true, output)
end
