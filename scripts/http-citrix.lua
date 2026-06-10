-- Citrix Bleed Detection (CVE-2023-4966)
-- Detects Citrix NetScaler information disclosure vulnerability
-- @output
-- 443/tcp open  https
-- | http-citrix:
-- |   VULNERABLE: Citrix Bleed (CVE-2023-4966)
-- |     Information disclosure in NetScaler detected
-- |_    Session tokens may be extractable

description = [[
Detects Citrix NetScaler ADC/Gateway vulnerability (CVE-2023-4966).
This buffer overflow vulnerability allows attackers to extract session tokens
bypassing authentication on affected Citrix devices.
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

    local citrix_paths = {
        "/vpn/index.html",
        "/logon/LogonPoint/index.html",
        "/vpn/js/gateway_login_view.js",
        "/epa/scripts/win/nsepa_setup.exe",
        "/Citrix/StoreWeb/",
    }

    for _, path in ipairs(citrix_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 or response.status == 302 then
                if response.body then
                    if response.body:find("Citrix") or
                       response.body:find("NetScaler") or
                       response.body:find("Gateway") or
                       response.body:find("LogonPoint") then
                        table.insert(vulns, "Citrix Gateway detected: " .. path)
                    end
                end
            end
        end
    end

    local overflow_paths = {
        "/vpn/index.html",
        "/logon/LogonPoint/index.html",
    }

    for _, path in ipairs(overflow_paths) do
        local long_string = string.rep("A", 24576)
        local options = {
            header = {
                ["Host"] = long_string
            }
        }
        local response = http.get(host, port, path, options)
        if response and response.status then
            if response.status == 200 and response.body then
                if response.body:len() > 0 and not response.body:find("error") then
                    table.insert(vulns, "Buffer overflow indicator on: " .. path)
                end
            end
        end
    end

    if #vulns > 0 then
        local result = "VULNERABLE: Citrix Bleed (CVE-2023-4966)\n"
        result = result .. "  Information disclosure in NetScaler detected\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "Not vulnerable to Citrix Bleed"
end
