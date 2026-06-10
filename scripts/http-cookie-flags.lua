-- Cookie Security Flags Check
-- Validates security attributes on HTTP cookies

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Checks HTTP cookies for missing security flags such as Secure,
HttpOnly, and SameSite attributes.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response or not response.header then
        return "No HTTP response received"
    end

    local cookies = response.header["set-cookie"]

    if not cookies then
        table.insert(output, "No cookies found in response")
        return stdnse.format_output(true, output)
    end

    if type(cookies) == "string" then
        cookies = {cookies}
    end

    table.insert(output, "Cookies Found: " .. #cookies)
    table.insert(output, "")

    local issues = {}

    for i, cookie in ipairs(cookies) do
        local name = cookie:match("^([^=]+)=") or "unknown"
        table.insert(output, "Cookie #" .. i .. ": " .. name)

        if not cookie:find("[Ss]ecure") then
            table.insert(output, "  [!] Missing Secure flag")
            table.insert(issues, name .. " missing Secure flag")
        end

        if not cookie:find("[Hh]ttp[Oo]nly") then
            table.insert(output, "  [!] Missing HttpOnly flag")
            table.insert(issues, name .. " missing HttpOnly flag")
        end

        if not cookie:find("[Ss]ame[Ss]ite") then
            table.insert(output, "  [!] Missing SameSite attribute")
            table.insert(issues, name .. " missing SameSite attribute")
        end

        if cookie:find("SameSite=None") and not cookie:find("[Ss]ecure") then
            table.insert(output, "  [!] SameSite=None without Secure is invalid")
            table.insert(issues, name .. " has SameSite=None without Secure")
        end

        table.insert(output, "")
    end

    if #issues > 0 then
        table.insert(output, "[!] Cookie Security Issues: " .. #issues)
    else
        table.insert(output, "[+] All cookies have proper security flags")
    end

    return stdnse.format_output(true, output)
end
