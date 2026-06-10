-- Insecure Redirect Detection
-- Detects insecure HTTP redirects

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects insecure redirect chains where HTTPS redirects to HTTP
or where sensitive pages redirect to insecure destinations.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local findings = {}

    local sensitive_paths = {"/login", "/admin", "/account", "/dashboard",
                             "/profile", "/settings", "/checkout", "/payment"}

    for _, path in ipairs(sensitive_paths) do
        local r = http.get(host.ip, port, path, {redirect = false})
        if r and r.status and (r.status == 301 or r.status == 302 or
                               r.status == 303 or r.status == 307 or r.status == 308) then
            local location = r.header and r.header["location"]
            if location then
                if location:match("^http://") then
                    table.insert(findings, {
                        path = path,
                        redirect_to = location,
                        type = "HTTPS to HTTP redirect"
                    })
                elseif location:find("evil%.com") or location:find("attacker%.com") then
                    table.insert(findings, {
                        path = path,
                        redirect_to = location,
                        type = "Open redirect"
                    })
                end
            end
        end
    end

    local base_r = http.get(host.ip, port, "/", {redirect = false})
    if base_r and base_r.header and base_r.header["location"] then
        local loc = base_r.header["location"]
        if loc:match("^http://") and port.service == "https" then
            table.insert(findings, {
                path = "/",
                redirect_to = loc,
                type = "Root HTTPS to HTTP redirect"
            })
        end
    end

    if #findings > 0 then
        table.insert(output, "Insecure Redirects Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] Path: " .. f.path)
            table.insert(output, "[!]   Redirects to: " .. f.redirect_to)
            table.insert(output, "[!]   Issue: " .. f.type)
            table.insert(output, "")
        end
        table.insert(output, "[!] MEDIUM: Insecure redirects expose credentials")
        return stdnse.format_output(true, output)
    end

    return nil
end
