-- HTTP Cookie Enumeration
-- Analyzes cookies for security issues

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates and analyzes HTTP cookies for security flags,
secure attributes, and potential vulnerabilities.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local findings = {}

    local paths = {"/", "/login", "/admin", "/api"}
    local all_cookies = {}

    for _, path in ipairs(paths) do
        local r = http.get(host.ip, port, path)
        if r and r.header then
            local set_cookie = r.header["set-cookie"]
            if set_cookie then
                local cookies = type(set_cookie) == "table" and set_cookie or {set_cookie}
                for _, cookie in ipairs(cookies) do
                    local name = cookie:match("^([^=]+)")
                    if name then
                        table.insert(all_cookies, {
                            name = name,
                            raw = cookie,
                            path = path
                        })
                    end
                end
            end
        end
    end

    if #all_cookies == 0 then
        table.insert(output, "[-] No cookies found")
        return stdnse.format_output(true, output)
    end

    table.insert(output, "Cookie Enumeration")
    table.insert(output, "")

    for _, cookie in ipairs(all_cookies) do
        table.insert(output, "[!] Cookie: " .. cookie.name .. " (from " .. cookie.path .. ")")
        table.insert(output, "    Raw: " .. cookie.raw)

        local raw_lower = cookie.raw:lower()
        if not raw_lower:find("secure") then
            table.insert(findings, cookie.name .. " missing Secure flag")
        end
        if not raw_lower:find("httponly") then
            table.insert(findings, cookie.name .. " missing HttpOnly flag")
        end
        if not raw_lower:find("samesite") then
            table.insert(findings, cookie.name .. " missing SameSite attribute")
        end
        if raw_lower:find("expires=") then
            local expiry = cookie.raw:match("[Ee]xpires=([^;]+)")
            if expiry and expiry:find("2099") then
                table.insert(findings, cookie.name .. " has far-future expiry")
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "")
        table.insert(output, "Cookie Security Issues:")
        for _, f in ipairs(findings) do
            table.insert(output, "  [!] " .. f)
        end
    end

    return stdnse.format_output(true, output)
end
