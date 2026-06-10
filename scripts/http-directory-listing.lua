-- Directory Listing Detection
-- Checks for enabled directory listing on web servers

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Tests common directories for directory listing enabled
on the web server which could expose sensitive files.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

action = function(host, port)
    local output = {}
    local found = 0

    local paths = {
        "/", "/images/", "/uploads/", "/files/", "/backup/",
        "/admin/", "/data/", "/temp/", "/logs/", "/css/",
        "/js/", "/scripts/", "/includes/", "/assets/", "/static/",
        "/content/", "/media/", "/documents/", "/download/", "/resources/"
    }

    table.insert(output, "Testing " .. #paths .. " common directories")
    table.insert(output, "")

    for _, path in ipairs(paths) do
        local response = http.get(host.ip, port, path)

        if response and response.status == 200 then
            local body = response.body or ""
            local is_listing = false

            if body:find("Index of") or
               body:find("Directory listing") or
               body:find("<title>Index of") or
               body:find("Parent Directory") or
               body:find("Last modified") then
                is_listing = true
            end

            if is_listing then
                found = found + 1
                table.insert(output, "[!] Directory listing enabled: " .. path)
            end
        end
    end

    table.insert(output, "")
    if found > 0 then
        table.insert(output, "[!] Found " .. found .. " directories with listing enabled")
        table.insert(output, "[!] Attackers can enumerate and access exposed files")
    else
        table.insert(output, "[+] No directory listing found on tested paths")
    end

    return stdnse.format_output(true, output)
end
