-- JBoss/WildFly Information Disclosure
-- Extracts JBoss version and configuration details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects JBoss/WildFly application server information disclosure
including version, admin consoles, and exposed management endpoints.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 9990 or
            port.number == 8443)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "JBoss/WildFly Information Disclosure")
    table.insert(output, "")

    local server = response.header and response.header["server"]
    local is_jboss = false

    if server and (server:lower():find("jboss") or server:lower():find("wildfly")) then
        is_jboss = true
        table.insert(output, "[!] Server: " .. server)
    end

    local paths = {
        {"/admin-console", "Admin Console"},
        {"/jmx-console", "JMX Console"},
        {"/web-console", "Web Console"},
        {"/invoker/JMXInvokerServlet", "JMX Invoker Servlet"},
        {"/management", "Management API"},
        {"/console", "Management Console"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status and r.status ~= 404 then
            is_jboss = true
            table.insert(output, "[!] " .. check[2] .. " found at " .. check[1] .. " (HTTP " .. r.status .. ")")
        end
    end

    if response.body and (response.body:find("JBoss") or response.body:find("WildFly")) then
        is_jboss = true
        table.insert(output, "[!] JBoss/WildFly branding in page body")
    end

    if not is_jboss then
        table.insert(output, "[-] JBoss/WildFly not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] JBoss disclosure aids deserialization exploit targeting")

    return stdnse.format_output(true, output)
end
