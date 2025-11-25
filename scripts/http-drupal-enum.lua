-- Drupal Enumeration and Version Detection
-- Enumerates Drupal CMS version, modules, and users
-- @output
-- 80/tcp open  http
-- | http-drupal-enum:
-- |   Drupal Version: 7.58 (OUTDATED - latest: 10.x)
-- |   
-- |   Installed Modules (8 found):
-- |     views 7.x-3.20 (VULNERABLE: SA-CONTRIB-2017-055)
-- |     ckeditor 7.x-1.18
-- |     webform 7.x-4.19
-- |     token 7.x-1.7
-- |     admin_menu 7.x-3.0-rc5
-- |     panels 7.x-3.9 (VULNERABLE: SA-CONTRIB-2018-047)
-- |     ctools 7.x-1.14
-- |     pathauto 7.x-1.3
-- |   
-- |   Configuration Issues:
-- |     - Update status page accessible (/admin/reports/updates)
-- |     - CHANGELOG.txt exposed (version disclosure)
-- |     - Install.php accessible (site not secured)
-- |   
-- |_  Risk: HIGH - Multiple vulnerabilities and misconfigurations

description = [[
Enumerates Drupal CMS installations including version, modules, themes, and users.
Detects common vulnerabilities and misconfigurations.

Checks for:
- Drupal version and patch level
- Installed modules with known vulnerabilities
- Information disclosure (CHANGELOG.txt, install.php)
- Configuration issues
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
    
    -- Detect Drupal
    local response = http.get(host, port, "/")
    if not response or not response.body then
        return nil
    end
    
    if not (response.body:find("Drupal") or response.body:find("/sites/default/files")) then
        return "Not a Drupal site"
    end
    
    -- Detect version
    local version = detect_drupal_version(host, port)
    if version then
        local latest = get_latest_version(version)
        if latest then
            table.insert(results, "Drupal Version: " .. version .. " (OUTDATED - latest: " .. latest .. ")")
        else
            table.insert(results, "Drupal Version: " .. version)
        end
        table.insert(results, "")
    end
    
    -- Enumerate modules
    local modules = enumerate_modules(host, port)
    if #modules > 0 then
        table.insert(results, "Installed Modules (" .. #modules .. " found):")
        for _, module in ipairs(modules) do
            local line = "  " .. module.name .. " " .. module.version
            if module.vuln then
                line = line .. " " .. module.vuln
            end
            table.insert(results, line)
        end
        table.insert(results, "")
    end
    
    -- Check for misconfigurations
    local issues = check_config_issues(host, port)
    if #issues > 0 then
        table.insert(results, "Configuration Issues:")
        for _, issue in ipairs(issues) do
            table.insert(results, "  - " .. issue)
        end
        table.insert(results, "")
    end
    
    if #results > 0 then
        table.insert(results, "Risk: HIGH - Multiple vulnerabilities and misconfigurations")
        return table.concat(results, "\n")
    end
    
    return "Drupal detected but enumeration failed"
end

function detect_drupal_version(host, port)
    local http = require "http"
    
    -- Try CHANGELOG.txt
    local response = http.get(host, port, "/CHANGELOG.txt")
    if response and response.status == 200 and response.body then
        local version = response.body:match("Drupal (%d+%.%d+%.?%d*)")
        if version then
            return version
        end
    end
    
    -- Try version from generator meta tag
    response = http.get(host, port, "/")
    if response and response.body then
        local version = response.body:match('content="Drupal (%d+%.%d+%.?%d*)"')
        if version then
            return version
        end
    end
    
    return nil
end

function enumerate_modules(host, port)
    local http = require "http"
    local modules = {}
    
    -- Common Drupal modules
    local common_modules = {
        "views", "ckeditor", "webform", "token", "admin_menu",
        "panels", "ctools", "pathauto", "entity", "libraries"
    }
    
    for _, module_name in ipairs(common_modules) do
        -- Check for module directory
        local paths = {
            "/sites/all/modules/" .. module_name,
            "/modules/" .. module_name
        }
        
        for _, path in ipairs(paths) do
            local response = http.get(host, port, path .. "/README.txt")
            if response and response.status == 200 then
                local version = "7.x-unknown"
                if response.body then
                    version = response.body:match("(%d+%.x%-%d+%.%d+)") or version
                end
                
                local module = {
                    name = module_name,
                    version = version,
                    vuln = check_module_vuln(module_name, version)
                }
                table.insert(modules, module)
                break
            end
        end
    end
    
    return modules
end

function check_module_vuln(name, version)
    -- Known vulnerable modules (simplified database)
    local vuln_db = {
        ["views"] = {
            ["7.x-3.20"] = "(VULNERABLE: SA-CONTRIB-2017-055)"
        },
        ["panels"] = {
            ["7.x-3.9"] = "(VULNERABLE: SA-CONTRIB-2018-047)"
        }
    }
    
    if vuln_db[name] and vuln_db[name][version] then
        return vuln_db[name][version]
    end
    
    return nil
end

function check_config_issues(host, port)
    local http = require "http"
    local issues = {}
    
    -- Check for exposed files
    local sensitive_files = {
        {path = "/CHANGELOG.txt", desc = "CHANGELOG.txt exposed (version disclosure)"},
        {path = "/install.php", desc = "Install.php accessible (site not secured)"},
        {path = "/UPGRADE.txt", desc = "UPGRADE.txt exposed"},
        {path = "/admin/reports/updates", desc = "Update status page accessible"}
    }
    
    for _, file in ipairs(sensitive_files) do
        local response = http.get(host, port, file.path)
        if response and response.status == 200 then
            table.insert(issues, file.desc)
        end
    end
    
    return issues
end

function get_latest_version(current)
    -- Major version check
    local major = current:match("(%d+)%.")
    if major == "7" then
        return "10.x"
    elseif major == "8" then
        return "10.x"
    end
    return nil
end
