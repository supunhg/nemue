-- ProxyLogon Detection (CVE-2021-26855)
-- Detects Microsoft Exchange Server SSRF vulnerability
-- @output
-- 443/tcp open  https
-- | http-proxylogon:
-- |   VULNERABLE: ProxyLogon (CVE-2021-26855)
-- |     Exchange Server SSRF detected
-- |_    Path: /owa/auth/x.js

description = [[
Detects Microsoft Exchange Server ProxyLogon vulnerability (CVE-2021-26855).
This SSRF vulnerability allows unauthenticated attackers to execute arbitrary
commands on vulnerable Exchange servers.
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

    local exchange_paths = {
        "/owa/auth/x.js",
        "/ecp/x.js",
        "/owa/",
        "/ecp/"
    }

    for _, path in ipairs(exchange_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 or response.status == 302 then
                if response.body then
                    local server = response.header and response.header["x-owa-version"]
                    if server then
                        table.insert(vulns, "Exchange version detected: " .. server)
                    end
                end
            end
        end
    end

    local ssrf_paths = {
        "/owa/auth/..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2F..%2FWindows%2FSystem32%2Fcmd.exe",
        "/ecp/proxyLogon.ecp",
    }

    for _, path in ipairs(ssrf_paths) do
        local options = {
            header = {
                ["Cookie"] = "X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/proxyLogon.ecp"
            }
        }
        local response = http.get(host, port, path, options)
        if response and response.status then
            if response.status == 200 or response.status == 241 then
                table.insert(vulns, "SSRF indicator detected on: " .. path)
            end
        end
    end

    if #vulns > 0 then
        local result = "VULNERABLE: ProxyLogon (CVE-2021-26855)\n"
        result = result .. "  Exchange Server SSRF detected\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "Not vulnerable to ProxyLogon"
end
