-- Git repository disclosure check
description = [[
Checks for exposed Git repositories that could leak source code,
credentials, and other sensitive information.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "safe"}

portrule = function(port)
    return port.service and port.service:lower():match("http")
end

action = function(host, port)
    local http = require "http"
    local result = {}
    
    -- Git files to check
    local git_files = {
        "/.git/HEAD",
        "/.git/config",
        "/.git/index",
        "/.git/logs/HEAD",
        "/.git/refs/heads/master",
        "/.git/refs/heads/main"
    }
    
    local found = false
    
    for _, file in ipairs(git_files) do
        local response = http.get(host, port, file)
        
        if response and response.status == 200 then
            if not found then
                table.insert(result, "CRITICAL: Git repository exposed!")
                found = true
            end
            
            table.insert(result, string.format("  Accessible: %s", file))
            
            -- Parse HEAD to find branch
            if file == "/.git/HEAD" and response.body then
                local branch = response.body:match("ref: refs/heads/(%S+)")
                if branch then
                    table.insert(result, string.format("  Current branch: %s", branch))
                end
            end
            
            -- Parse config for remote URLs
            if file == "/.git/config" and response.body then
                for url in response.body:gmatch("url = ([^\n]+)") do
                    table.insert(result, string.format("  Remote URL: %s", url))
                end
            end
        end
    end
    
    if found then
        table.insert(result, "")
        table.insert(result, "Impact: Full source code disclosure possible")
        table.insert(result, "Recommendation: Remove .git directory from web root")
        table.insert(result, "Tools: git-dumper, GitHack, dvcs-ripper")
        return table.concat(result, "\n")
    end
    
    return nil
end
