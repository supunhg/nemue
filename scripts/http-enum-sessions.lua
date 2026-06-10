-- HTTP Session Enumeration
-- Analyzes session management mechanisms

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates and analyzes session management including session ID
generation, token entropy, and session fixation vulnerabilities.
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

    local session_names = {"PHPSESSID", "JSESSIONID", "ASP.NET_SessionId",
                           "session", "sid", "sess_id", "connect.sid",
                           "_session_id", "rack.session", "csrf_token"}

    local r1 = http.get(host.ip, port, "/")
    local r2 = http.get(host.ip, port, "/")

    if not r1 or not r1.header then
        return "No HTTP response received"
    end

    table.insert(output, "Session Enumeration")
    table.insert(output, "")

    local set_cookie = r1.header["set-cookie"]
    if set_cookie then
        local cookies = type(set_cookie) == "table" and set_cookie or {set_cookie}
        for _, cookie in ipairs(cookies) do
            local name = cookie:match("^([^=]+)")
            local value = cookie:match("^[^=]+=([^;]+)")
            if name and value then
                table.insert(output, "[!] Session cookie: " .. name .. "=" .. value)

                if #value < 16 then
                    table.insert(findings, name .. " has low entropy (" .. #value .. " chars)")
                end

                if value:match("^%d+$") then
                    table.insert(findings, name .. " appears to be sequential numeric")
                end

                for _, known in ipairs(session_names) do
                    if name == known then
                        table.insert(output, "    Known session mechanism: " .. name)
                    end
                end
            end
        end
    end

    if r2 and r2.header then
        local set_cookie2 = r2.header["set-cookie"]
        if set_cookie and set_cookie2 then
            local v1 = set_cookie:match("^[^=]+=([^;]+)")
            local v2 = set_cookie2:match("^[^=]+=([^;]+)")
            if v1 and v2 and v1 == v2 then
                table.insert(findings, "Session ID is reused across requests (possible fixation)")
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "")
        table.insert(output, "Session Issues:")
        for _, f in ipairs(findings) do
            table.insert(output, "  [!] " .. f)
        end
    end

    return stdnse.format_output(true, output)
end
