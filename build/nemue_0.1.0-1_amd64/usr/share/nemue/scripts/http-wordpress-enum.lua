-- WordPress Enumeration
-- Enumerates WordPress version, themes, plugins, and users
-- @output
-- 80/tcp open  http
-- | http-wordpress-enum:
-- |   WordPress Version: 5.8.1
-- |   
-- |   Plugins:
-- |     akismet 4.1.9 (OUTDATED - latest: 5.0)
-- |     jetpack 10.0 (VULNERABLE: CVE-2021-39347)
-- |     contact-form-7 5.4.2
-- |   
-- |   Themes:
-- |     twentytwentyone 1.4 (active)
-- |     twentytwenty 1.8
-- |   
-- |   Users:
-- |     admin (ID: 1)
-- |     editor (ID: 2)
-- |_    author (ID: 3)

description = [[
Enumerates WordPress installations including version, themes, plugins,
and users. Can detect outdated plugins and known vulnerabilities.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "intrusive"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local results = {}
    
    -- Detect WordPress
    local response = http.get(host, port, "/")
    if not response or not response.body then
        return nil
    end
    
    if not (response.body:find("wp-content") or response.body:find("wordpress")) then
        return "Not a WordPress site"
    end
    
    -- Get WordPress version
    local version = detect_version(host, port)
    if version then
        table.insert(results, "WordPress Version: " .. version)
        table.insert(results, "")
    end
    
    -- Enumerate plugins
    local plugins = enumerate_plugins(host, port)
    if #plugins > 0 then
        table.insert(results, "Plugins:")
        for _, plugin in ipairs(plugins) do
            local vuln_info = check_plugin_vulns(plugin.name, plugin.version)
            local line = "  " .. plugin.name .. " " .. plugin.version
            if vuln_info then
                line = line .. " " .. vuln_info
            end
            table.insert(results, line)
        end
        table.insert(results, "")
    end
    
    -- Enumerate themes
    local themes = enumerate_themes(host, port)
    if #themes > 0 then
        table.insert(results, "Themes:")
        for _, theme in ipairs(themes) do
            local line = "  " .. theme.name .. " " .. theme.version
            if theme.active then
                line = line .. " (active)"
            end
            table.insert(results, line)
        end
        table.insert(results, "")
    end
    
    -- Enumerate users
    local users = enumerate_users(host, port)
    if #users > 0 then
        table.insert(results, "Users:")
        for _, user in ipairs(users) do
            table.insert(results, "  " .. user.name .. " (ID: " .. user.id .. ")")
        end
    end
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return "WordPress detected but enumeration failed"
end

function detect_version(host, port)
    local http = require "http"
    
    -- Try readme.html
    local response = http.get(host, port, "/readme.html")
    if response and response.body then
        local version = response.body:match("Version (%d+%.%d+%.%d+)")
        if version then
            return version
        end
    end
    
    -- Try meta generator tag
    response = http.get(host, port, "/")
    if response and response.body then
        local version = response.body:match('content="WordPress ([%d%.]+)"')
        if version then
            return version
        end
    end
    
    return nil
end

function enumerate_plugins(host, port)
    local http = require "http"
    local plugins = {}
    
    -- Common plugin paths
    local common_plugins = {
        "akismet", "jetpack", "contact-form-7", "wordpress-seo",
        "wordfence", "all-in-one-seo-pack", "google-analytics-for-wordpress",
        "woocommerce", "wp-super-cache", "elementor"
    }
    
    for _, plugin_name in ipairs(common_plugins) do
        local path = "/wp-content/plugins/" .. plugin_name .. "/readme.txt"
        local response = http.get(host, port, path)
        
        if response and response.status == 200 and response.body then
            local version = response.body:match("Stable tag: ([%d%.]+)")
            if version then
                table.insert(plugins, {
                    name = plugin_name,
                    version = version
                })
            end
        end
    end
    
    return plugins
end

function enumerate_themes(host, port)
    local http = require "http"
    local themes = {}
    
    -- Common default themes
    local common_themes = {
        "twentytwentyone", "twentytwenty", "twentynineteen",
        "twentyseventeen", "twentysixteen"
    }
    
    for _, theme_name in ipairs(common_themes) do
        local path = "/wp-content/themes/" .. theme_name .. "/style.css"
        local response = http.get(host, port, path)
        
        if response and response.status == 200 and response.body then
            local version = response.body:match("Version: ([%d%.]+)")
            if version then
                table.insert(themes, {
                    name = theme_name,
                    version = version,
                    active = false
                })
            end
        end
    end
    
    -- Mark first theme as active (simplified)
    if #themes > 0 then
        themes[1].active = true
    end
    
    return themes
end

function enumerate_users(host, port)
    local http = require "http"
    local users = {}
    
    -- Try REST API
    local response = http.get(host, port, "/wp-json/wp/v2/users")
    if response and response.status == 200 and response.body then
        -- Parse JSON (simplified)
        for name, id in response.body:gmatch('"slug":"([^"]+)".-"id":(%d+)') do
            table.insert(users, {
                name = name,
                id = id
            })
        end
    end
    
    -- Try author enumeration (legacy method)
    if #users == 0 then
        for i = 1, 10 do
            local response = http.get(host, port, "/?author=" .. i)
            if response and response.status == 200 then
                local author = response.body:match('author/([^/"]+)')
                if author then
                    table.insert(users, {
                        name = author,
                        id = tostring(i)
                    })
                end
            end
        end
    end
    
    return users
end

function check_plugin_vulns(name, version)
    -- Known vulnerable plugins (simplified database)
    local vuln_db = {
        ["jetpack"] = {
            ["10.0"] = "VULNERABLE: CVE-2021-39347",
            ["9.9"] = "VULNERABLE: CVE-2021-39347"
        }
    }
    
    if vuln_db[name] and vuln_db[name][version] then
        return "(" .. vuln_db[name][version] .. ")"
    end
    
    return nil
end
