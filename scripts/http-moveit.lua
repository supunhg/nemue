-- MOVEit Detection (CVE-2023-34362)
-- Detects MOVEit Transfer SQL injection vulnerability
-- @output
-- 443/tcp open  https
-- | http-moveit:
-- |   VULNERABLE: MOVEit (CVE-2023-34362)
-- |     SQL injection in MOVEit Transfer detected
-- |_    Unauthenticated access possible

description = [[
Detects MOVEit Transfer vulnerability (CVE-2023-34362).
This SQL injection vulnerability allows unauthenticated attackers to gain
access to the MOVEit Transfer database and execute arbitrary code.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "http"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 443 or port.number == 80 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local vulns = {}

    local moveit_paths = {
        "/moveitisapi/moveitisapi.dll",
        "/moveitisapi/moveitisapi.dll?action=m2",
        "/human.aspx",
        "/guestaccess.aspx",
        "/api/v1/token",
        "/api/v1/folders"
    }

    for _, path in ipairs(moveit_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 or response.status == 302 then
                if response.body then
                    if response.body:find("MOVEit") or
                       response.body:find("moveitisapi") or
                       response.body:find("human%.aspx") then
                        table.insert(vulns, "MOVEit Transfer detected: " .. path)
                    end
                end
            end
        end
    end

    local sqli_paths = {
        "/moveitisapi/moveitisapi.dll?action=m2&tid=1'UNION+SELECT+1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32--",
        "/human.aspx?transaction=sign&msgid=1'OR'1'='1",
    }

    for _, path in ipairs(sqli_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 and response.body then
                if response.body:find("SQL") or response.body:find("syntax") or
                   response.body:find("error") then
                    table.insert(vulns, "SQL injection indicator on: " .. path)
                end
            end
        end
    end

    if #vulns > 0 then
        local result = "VULNERABLE: MOVEit (CVE-2023-34362)\n"
        result = result .. "  SQL injection in MOVEit Transfer detected\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "Not vulnerable to MOVEit CVE-2023-34362"
end
