-- Java Application Information Disclosure
-- Detects Java web application and framework details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Java web application information disclosure including
Spring, Struts, and other framework details through headers and error pages.
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
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Java Application Information Disclosure")
    table.insert(output, "")

    local is_java = false

    local powered = response.header and response.header["x-powered-by"]
    if powered and (powered:lower():find("servlet") or powered:lower():find("jsp")) then
        is_java = true
        table.insert(output, "[!] X-Powered-By: " .. powered)
    end

    local server = response.header and response.header["server"]
    if server and (server:lower():find("jetty") or server:lower():find("tomcat") or
                   server:lower():find("undertow") or server:lower():find("resin")) then
        is_java = true
        table.insert(output, "[!] Server: " .. server)
    end

    local err_response = http.get(host.ip, port, "/nonexistent_page_12345")
    if err_response and err_response.body then
        if err_response.body:find("java%.lang%.") or err_response.body:find("javax%.servlet") then
            is_java = true
            table.insert(output, "[!] Java stack trace exposed in error page")
        end
        if err_response.body:find("Spring") then
            is_java = true
            table.insert(output, "[!] Spring framework detected in error page")
        end
        if err_response.body:find("Struts") then
            is_java = true
            table.insert(output, "[!] Apache Struts detected in error page")
        end
        if err_response.body:find("HTTP Status") and err_response.body:find("Apache") then
            table.insert(output, "[!] Java application server error page")
        end
    end

    local paths = {
        {"/actuator", "Spring Boot Actuator"},
        {"/actuator/env", "Spring Boot environment"},
        {"/actuator/health", "Spring Boot health"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status == 200 then
            is_java = true
            table.insert(output, "[!] " .. check[2] .. " accessible at " .. check[1])
        end
    end

    if not is_java then
        table.insert(output, "[-] Java not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] Java disclosure aids deserialization exploit targeting")

    return stdnse.format_output(true, output)
end
