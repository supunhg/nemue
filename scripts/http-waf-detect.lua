-- WAF Detection
-- Detects Web Application Firewalls and protection mechanisms

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Detects Web Application Firewalls by analyzing HTTP responses
for WAF-specific headers, pages, and behavior patterns.
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
    local wafs = {}

    local malicious_path = "/<script>alert(1)</script>"
    local response = http.get(host.ip, port, malicious_path)

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "WAF Detection Scan")
    table.insert(output, "")

    if response.status == 403 or response.status == 406 or response.status == 419 or response.status == 429 or response.status == 501 or response.status == 503 then
        table.insert(output, "[!] Request blocked with status: " .. response.status)

        local body = response.body or ""
        local headers = response.header or {}

        local waf_signatures = {
            {"Cloudflare", {"cf-ray", "server: cloudflare"}},
            {"AWS WAF", {"x-amzn-requestid", "x-amzn-errortype"}},
            {"Akamai", {"x-akamai", "akamai"}},
            {"Incapsula/Imperva", {"x-iinfo", "incap_ses"}},
            {"F5 BIG-IP", {"x-waf", "bigipserver"}},
            {"ModSecurity", {"mod_security", "NOYB"}},
            {"Sucuri", {"x-sucuri", "sucuri"}},
            {"Wordfence", {"wordfence"}},
            {"Barracuda", {"barra"}},
            {"Citrix NetScaler", {"ns_af", "citrix"}},
            {"FortiWeb", {"fortigate", "fortiweb"}},
            {"DenyAll", {"sessioncookie"}},
            {"WebKnight", {"webknight"}},
            {"dotDefender", {"dotdefender"}},
            {"Safe3", {"safe3"}},
            {"KnownSec", {"ks-waf"}}
        }

        for _, waf in ipairs(waf_signatures) do
            local name = waf[1]
            local sigs = waf[2]

            for _, sig in ipairs(sigs) do
                local found = false

                for header_name, header_value in pairs(headers) do
                    if (header_name .. ": " .. tostring(header_value)):lower():find(sig:lower()) then
                        found = true
                        break
                    end
                end

                if body:lower():find(sig:lower()) then
                    found = true
                end

                if found then
                    table.insert(wafs, name)
                    break
                end
            end
        end

        if #wafs > 0 then
            for _, waf in ipairs(wafs) do
                table.insert(output, "[+] WAF Detected: " .. waf)
            end
        else
            table.insert(output, "[!] Request blocked but WAF type unknown")
        end
    else
        table.insert(output, "[+] No WAF detected or WAF not blocking test payload")
        table.insert(output, "    Response status: " .. response.status)
    end

    table.insert(output, "")
    table.insert(output, "[!] WAF detection helps plan penetration testing approach")

    return stdnse.format_output(true, output)
end
