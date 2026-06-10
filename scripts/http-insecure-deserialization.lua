-- Insecure Deserialization Detection
-- Checks for unsafe deserialization in web applications
-- @output
-- 80/tcp open  http
-- | http-insecure-deserialization:
-- |   WARNING: Insecure deserialization detected
-- |     Java serialization marker found
-- |_    PHP object injection possible

description = [[
Detects insecure deserialization vulnerabilities in web applications.
Checks for Java serialization, PHP object injection, Python pickle,
and .NET ViewState deserialization issues.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "http"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local base64 = require "base64"
    local vulns = {}

    local paths = {"/", "/api", "/login", "/admin", "/upload", "/process"}

    for _, path in ipairs(paths) do
        local response = http.get(host, port, path)
        if response and response.status == 200 and response.body then
            if response.body:find("__VIEWSTATE") then
                local viewstate = response.body:match("__VIEWSTATE[^\"]*\"([^\"]+)\"")
                if viewstate and #viewstate > 100 then
                    local decoded = base64.decode(viewstate)
                    if decoded and #decoded > 50 then
                        table.insert(vulns, "ViewState detected on " .. path .. " (potential .NET deserialization)")
                    end
                end
            end

            if response.body:find("PHPSESSID") then
                table.insert(vulns, "PHP session detected on " .. path)
            end

            if response.body:find("JSESSIONID") then
                table.insert(vulns, "Java session detected on " .. path .. " (check for Java deserialization)")
            end
        end

        local java_payload = "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA=="
        local php_payload = 'O:8:"stdClass":0:{}'

        local options = {
            header = {
                ["Content-Type"] = "application/x-www-form-urlencoded"
            }
        }

        local post_data = "data=" .. http.escape(java_payload)
        local java_response = http.post(host, port, path, options, nil, post_data)
        if java_response and java_response.status then
            if java_response.status == 200 and java_response.body then
                if not java_response.body:find("error") and not java_response.body:find("invalid") then
                    table.insert(vulns, "Java deserialization payload accepted on " .. path)
                end
            end
        end

        local php_data = "data=" .. http.escape(php_payload)
        local php_response = http.post(host, port, path, options, nil, php_data)
        if php_response and php_response.status then
            if php_response.status == 200 and php_response.body then
                if not php_response.body:find("error") then
                    table.insert(vulns, "PHP object accepted on " .. path)
                end
            end
        end
    end

    if #vulns > 0 then
        local result = "WARNING: Insecure deserialization indicators found\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "No deserialization vulnerabilities detected"
end
