-- Directory Listing Detection
-- Checks for enabled directory listings
-- @output
-- 80/tcp open  http
-- | http-enum-directories:
-- |   Directory Listing Found:
-- |     /uploads/ (13 files)
-- |     /backup/ (5 files)
-- |_    /logs/ (23 files)

description = [[
Scans for web directories that have directory listing enabled,
which can expose sensitive files and directory structure.
Tests common directories and looks for auto-index patterns.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    
    local findings = {}
    
    -- Common directories to check
    local directories = {
        "/uploads/", "/images/", "/files/", "/documents/", "/assets/",
        "/backup/", "/backups/", "/bak/", "/old/", "/tmp/", "/temp/",
        "/logs/", "/log/", "/data/", "/downloads/", "/public/",
        "/static/", "/media/", "/content/", "/resources/",
        "/includes/", "/lib/", "/libs/", "/vendor/", "/node_modules/"
    }
    
    for _, dir in ipairs(directories) do
        local response = http.get(host, port, dir)
        
        if response and response.status == 200 and response.body then
            local body = response.body
            
            -- Check for directory listing indicators
            local is_listing = false
            local file_count = 0
            
            -- Apache mod_autoindex
            if body:find("<title>Index of") or body:find("Parent Directory") then
                is_listing = true
                -- Count files in listing
                for _ in body:gmatch("<a href=\"[^\"]+\">") do
                    file_count = file_count + 1
                end
            end
            
            -- nginx autoindex
            if body:find("<h1>Index of") or body:find("nginx/") and body:find("<hr>") then
                is_listing = true
                for _ in body:gmatch("<a href=\"[^\"]+\">") do
                    file_count = file_count + 1
                end
            end
            
            -- IIS directory browsing
            if body:find("Directory Listing") or body:find("\\[To Parent Directory\\]") then
                is_listing = true
                for _ in body:gmatch("<A HREF=\"[^\"]+\">") do
                    file_count = file_count + 1
                end
            end
            
            -- Generic indicators
            if body:find("Parent Directory") or body:find("../") then
                if body:match("<table") and body:match("<a href") then
                    is_listing = true
                    for _ in body:gmatch("<a href=\"[^\"]+\">") do
                        file_count = file_count + 1
                    end
                end
            end
            
            if is_listing then
                local severity = "INFO"
                
                -- Check for sensitive files
                local sensitive_patterns = {
                    "%.sql", "%.db", "%.bak", "%.old", "%.backup",
                    "%.key", "%.pem", "%.p12", "%.pfx",
                    "%.conf", "%.config", "%.env",
                    "%.log", "%.txt", "%.csv"
                }
                
                for _, pattern in ipairs(sensitive_patterns) do
                    if body:find(pattern) then
                        severity = "HIGH"
                        break
                    end
                end
                
                if file_count > 2 then  -- Exclude "." and ".."
                    local entry = dir .. " (" .. (file_count - 2) .. " files)"
                    if severity == "HIGH" then
                        entry = entry .. " [SENSITIVE FILES DETECTED]"
                    end
                    table.insert(findings, entry)
                end
            end
        end
    end
    
    if #findings > 0 then
        local result = "Directory Listing Found:\n"
        for _, finding in ipairs(findings) do
            result = result .. "  " .. finding .. "\n"
        end
        return result
    end
    
    return nil
end
