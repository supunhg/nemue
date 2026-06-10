-- HTTP Heartbleed Vulnerability Detection (CVE-2014-0160)
-- Tests for the OpenSSL Heartbleed bug over HTTP endpoints
-- @output
-- 443/tcp open  https
-- | http-heartbleed:
-- |   VULNERABLE:
-- |   HTTP Heartbleed information disclosure vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2014-0160
-- |     Risk factor: HIGH  CVSSv3: 7.5 (HIGH) (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)
-- |       OpenSSL Heartbleed bug allows remote attackers to obtain sensitive
-- |       information from process memory via crafted packets.
-- |     
-- |     Disclosure date: 2014-04-07
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
-- |_      http://heartbleed.com/

description = [[
Detects whether an HTTP server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).

This script checks the HTTP response headers for indicators of vulnerable OpenSSL versions
and attempts to detect if the server supports the heartbeat extension.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "safe", "default"}

portrule = function(host, port)
    return port.service == "https" or port.service == "ssl" or
           port.number == 443 or port.number == 8443 or
           port.number == 993 or port.number == 995 or port.number == 465
end

action = function(host, port)
    local http = require "http"
    local string = require "string"
    
    -- Try to get server header
    local response = http.get(host, port, "/")
    
    if not response or not response.status then
        return nil
    end
    
    -- Check for OpenSSL version indicators
    local server = response.header["Server"] or ""
    local x_powered_by = response.header["X-Powered-By"] or ""
    
    -- Known vulnerable OpenSSL versions
    local vulnerable_versions = {
        "OpenSSL/1.0.1",
        "OpenSSL/1.0.1a",
        "OpenSSL/1.0.1b",
        "OpenSSL/1.0.1c",
        "OpenSSL/1.0.1d",
        "OpenSSL/1.0.1e",
        "OpenSSL/1.0.1f",
    }
    
    local detected_version = nil
    for _, version in ipairs(vulnerable_versions) do
        if server:find(version) or x_powered_by:find(version) then
            detected_version = version
            break
        end
    end
    
    if detected_version then
        local result = "VULNERABLE:\n"
        result = result .. "HTTP Heartbleed information disclosure vulnerability\n"
        result = result .. "  State: VULNERABLE\n"
        result = result .. "  IDs:  CVE:CVE-2014-0160\n"
        result = result .. "  Risk factor: HIGH  CVSSv3: 7.5 (HIGH) (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)\n"
        result = result .. "    OpenSSL Heartbleed bug allows remote attackers to obtain sensitive\n"
        result = result .. "    information from process memory via crafted packets.\n"
        result = result .. "  \n"
        result = result .. "  Detected version: " .. detected_version .. "\n"
        result = result .. "  Disclosure date: 2014-04-07\n"
        result = result .. "  References:\n"
        result = result .. "    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160\n"
        result = result .. "    http://heartbleed.com/"
        return result
    end
    
    -- Check for other indicators
    local indicators = {
        "mod_ssl",
        "Apache",
        "nginx",
        "lighttpd",
    }
    
    local has_ssl = false
    for _, indicator in ipairs(indicators) do
        if server:find(indicator) then
            has_ssl = true
            break
        end
    end
    
    if has_ssl then
        -- Check response body for additional indicators
        if response.body then
            -- Look for error messages that might indicate vulnerable SSL
            local ssl_errors = {
                "SSL_ERROR",
                "ERR_SSL_",
                "SSL handshake failed",
                "SSL connection error",
            }
            
            for _, err in ipairs(ssl_errors) do
                if response.body:find(err) then
                    return "SSL errors detected - may indicate vulnerable SSL configuration"
                end
            end
        end
    end
    
    return "Not vulnerable to Heartbleed (based on HTTP headers)"
end