-- Default Credentials Detection
-- Tests common default credentials on web applications

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for default credentials on common web applications and
admin interfaces including Tomcat, Jenkins, phpMyAdmin, and others.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

local default_creds = {
    {"/manager/html", "Tomcat Manager", {{"tomcat", "tomcat"}, {"admin", "admin"}, {"admin", ""}}},
    {"/jenkins/login", "Jenkins", {{"admin", "admin"}, {"jenkins", "jenkins"}}},
    {"/phpmyadmin/", "phpMyAdmin", {{"root", ""}, {"root", "root"}, {"admin", "admin"}}},
    {"/admin/", "Admin Panel", {{"admin", "admin"}, {"admin", "password"}, {"admin", "123456"}}},
    {"/wp-login.php", "WordPress", {{"admin", "admin"}, {"admin", "password"}}},
    {"/administrator/", "Joomla Admin", {{"admin", "admin"}}},
    {"/cpanel/", "cPanel", {{"root", "root"}}},
    {"/webmail/", "Webmail", {{"admin", "admin"}}},
}

action = function(host, port)
    local output = {}
    local findings = {}

    for _, cred_set in ipairs(default_creds) do
        local path = cred_set[1]
        local app = cred_set[2]
        local creds = cred_set[3]

        local r = http.get(host.ip, port, path)
        if r and r.status and r.status ~= 404 and r.status ~= 302 then
            for _, cred in ipairs(creds) do
                local user = cred[1]
                local pass = cred[2]
                local auth_response = http.post(host.ip, port, path, nil, nil,
                    {auth = {username = user, password = pass}})
                if auth_response and auth_response.status == 200 then
                    if not auth_response.body:find("login") and
                       not auth_response.body:find("password") and
                       not auth_response.body:find("incorrect") then
                        table.insert(findings, app .. " at " .. path .. " - " .. user .. ":" .. pass)
                        break
                    end
                end
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "Default Credentials Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] CRITICAL: Change default credentials immediately")
        return stdnse.format_output(true, output)
    end

    return nil
end
