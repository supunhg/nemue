-- HTTP User Enumeration
-- Enumerates valid usernames through web application responses

local http = require("http")
local stdnse = require("stdnse")

description = [[
Enumerates valid usernames by analyzing differential responses
from login forms, password reset pages, and registration forms.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "intrusive"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local findings = {}

    local test_users = {"admin", "administrator", "root", "user", "test",
                        "guest", "info", "support", "operator", "manager"}

    local login_paths = {"/login", "/login.php", "/wp-login.php",
                         "/admin/login", "/api/auth/login"}

    for _, path in ipairs(login_paths) do
        local check = http.get(host.ip, port, path)
        if check and check.status == 200 then
            local baseline_user = "nonexistent_user_xyz_12345"
            local baseline_r = http.post(host.ip, port, path, nil, nil,
                "username=" .. baseline_user .. "&password=test123")

            if baseline_r and baseline_r.body then
                local baseline_len = #baseline_r.body

                for _, user in ipairs(test_users) do
                    local r = http.post(host.ip, port, path, nil, nil,
                        "username=" .. user .. "&password=test123")
                    if r and r.body then
                        local len = #r.body
                        if math.abs(len - baseline_len) > 50 then
                            table.insert(findings, {
                                path = path,
                                user = user,
                                evidence = "Response differs from baseline"
                            })
                        end
                    end
                end
            end
        end
        if #findings > 0 then break end
    end

    if #findings > 0 then
        table.insert(output, "User Enumeration Possible:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] Path: " .. f.path)
            table.insert(output, "[!]   Valid user: " .. f.user)
            table.insert(output, "[!]   Evidence: " .. f.evidence)
        end
        table.insert(output, "")
        table.insert(output, "[!] MEDIUM: Username enumeration via differential responses")
        return stdnse.format_output(true, output)
    end

    return nil
end
