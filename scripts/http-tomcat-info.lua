-- Apache Tomcat Information Disclosure
-- Extracts Tomcat version and manager status

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Apache Tomcat information disclosure including version,
manager application status, and configuration details.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443 or
            port.number == 8009)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Apache Tomcat Information Disclosure")
    table.insert(output, "")

    local server = response.header and response.header["server"]
    local is_tomcat = false

    if server and server:lower():find("tomcat") then
        is_tomcat = true
        table.insert(output, "[!] Server: " .. server)
        local version = server:match("Tomcat/([%d%.]+)")
        if version then
            table.insert(output, "[!] Tomcat Version: " .. version)
        end
    end

    local paths = {
        {"/", "coyote", "Tomcat Coyote detected"},
        {"/manager/html", 401, "Manager application accessible"},
        {"/host-manager/html", 401, "Host Manager accessible"},
        {"/status", 200, "Status page accessible"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r then
            if type(check[2]) == "string" and r.body and r.body:lower():find(check[2]) then
                is_tomcat = true
                table.insert(output, "[!] " .. check[3])
            elseif type(check[2]) == "number" and r.status == check[2] then
                table.insert(output, "[!] " .. check[3])
            end
        end
    end

    if not is_tomcat then
        table.insert(output, "[-] Tomcat not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] Tomcat disclosure aids targeted exploitation")

    return stdnse.format_output(true, output)
end
