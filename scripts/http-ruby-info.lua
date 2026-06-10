-- Ruby Application Information Disclosure
-- Detects Ruby/Rails application details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Ruby on Rails and other Ruby framework information disclosure
including version, environment, and configuration details.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 3000 or port.number == 8080)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Ruby Application Information Disclosure")
    table.insert(output, "")

    local is_ruby = false

    local powered = response.header and response.header["x-powered-by"]
    if powered and powered:lower():find("phusion") then
        is_ruby = true
        table.insert(output, "[!] X-Powered-By: " .. powered)
    end

    local server = response.header and response.header["server"]
    if server and (server:lower():find("puma") or server:lower():find("unicorn") or
                   server:lower():find("passenger") or server:lower():find("thin")) then
        is_ruby = true
        table.insert(output, "[!] Server: " .. server)
    end

    local runtime = response.header and response.header["x-runtime"]
    if runtime then
        is_ruby = true
        table.insert(output, "[!] X-Runtime: " .. runtime)
    end

    local request_id = response.header and response.header["x-request-id"]
    if request_id then
        is_ruby = true
        table.insert(output, "[!] X-Request-ID: " .. request_id)
    end

    local err_response = http.get(host.ip, port, "/nonexistent_page_12345")
    if err_response and err_response.body then
        if err_response.body:find("Rails") then
            is_ruby = true
            table.insert(output, "[!] Rails error page detected")
        end
        if err_response.body:find("RAILS_ENV") or err_response.body:find("Rack%:%:") then
            table.insert(output, "[!] Rails/Rack environment details exposed")
        end
    end

    if not is_ruby then
        table.insert(output, "[-] Ruby/Rails not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] Ruby disclosure aids deserialization exploit targeting")

    return stdnse.format_output(true, output)
end
