-- Insecure Cookie Detection
-- Checks for cookies missing security attributes
-- @output
-- 443/tcp open  https
-- | http-cookie-flags:
-- |   Insecure Cookies Found:
-- |     session_id: Missing Secure flag
-- |     auth_token: Missing HttpOnly flag
-- |_    remember_me: Missing SameSite attribute

description = [[
Analyzes HTTP cookies for missing security flags:
- Secure flag (prevents transmission over HTTP)
- HttpOnly flag (prevents JavaScript access)
- SameSite attribute (prevents CSRF)
- Domain/Path scope issues
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "safe", "default"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    
    local issues = {}
    local cookies_found = 0
    
    -- Try common paths that set cookies
    local paths = {"/", "/login", "/admin", "/api", "/app"}
    
    for _, path in ipairs(paths) do
        local response = http.get(host, port, path, {bypass_cache = true})
        
        if response and response.header then
            local set_cookie = response.header["set-cookie"]
            
            if set_cookie then
                -- Handle multiple Set-Cookie headers
                local cookie_list = {}
                if type(set_cookie) == "table" then
                    cookie_list = set_cookie
                else
                    table.insert(cookie_list, set_cookie)
                end
                
                for _, cookie in ipairs(cookie_list) do
                    cookies_found = cookies_found + 1
                    
                    -- Extract cookie name
                    local cookie_name = cookie:match("^([^=]+)=")
                    if not cookie_name then
                        cookie_name = "unknown"
                    end
                    
                    -- Check for Secure flag
                    if not cookie:lower():find("secure") then
                        if port.number == 443 or port.service == "https" then
                            table.insert(issues, cookie_name .. ": Missing Secure flag")
                        end
                    end
                    
                    -- Check for HttpOnly flag
                    if not cookie:lower():find("httponly") then
                        -- Especially important for session/auth cookies
                        if cookie_name:lower():find("session") or 
                           cookie_name:lower():find("auth") or 
                           cookie_name:lower():find("token") then
                            table.insert(issues, cookie_name .. ": Missing HttpOnly flag (XSS risk)")
                        else
                            table.insert(issues, cookie_name .. ": Missing HttpOnly flag")
                        end
                    end
                    
                    -- Check for SameSite attribute
                    if not cookie:lower():find("samesite") then
                        table.insert(issues, cookie_name .. ": Missing SameSite attribute (CSRF risk)")
                    end
                    
                    -- Check for overly broad domain
                    local domain = cookie:match("[Dd]omain=([^;]+)")
                    if domain then
                        if domain:match("^%.") then
                            table.insert(issues, cookie_name .. ": Domain set to " .. domain .. " (too broad)")
                        end
                    end
                    
                    -- Check for long expiration
                    local expires = cookie:match("[Ee]xpires=([^;]+)")
                    local max_age = cookie:match("[Mm]ax%-[Aa]ge=(%d+)")
                    
                    if max_age then
                        local age_seconds = tonumber(max_age)
                        if age_seconds and age_seconds > 31536000 then  -- > 1 year
                            table.insert(issues, cookie_name .. ": Very long Max-Age (" .. 
                                       math.floor(age_seconds / 86400) .. " days)")
                        end
                    end
                end
            end
        end
    end
    
    if #issues > 0 then
        local result = "Insecure Cookies Found (" .. cookies_found .. " total):\n"
        for _, issue in ipairs(issues) do
            result = result .. "  " .. issue .. "\n"
        end
        return result
    end
    
    if cookies_found > 0 then
        return "All cookies have proper security attributes"
    end
    
    return nil
end
