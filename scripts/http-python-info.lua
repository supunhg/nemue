-- Python Application Information Disclosure
-- Detects Python web framework details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects Python web application information disclosure including
Django, Flask, and other framework details through headers and error pages.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8000 or port.number == 8080)
end

action = function(host, port)
    local output = {}
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "Python Application Information Disclosure")
    table.insert(output, "")

    local server = response.header and response.header["server"]
    local is_python = false

    if server and (server:lower():find("python") or server:lower():find("gunicorn") or
                   server:lower():find("uwsgi") or server:lower():find("waitress")) then
        is_python = true
        table.insert(output, "[!] Server: " .. server)
    end

    local powered = response.header and response.header["x-powered-by"]
    if powered and powered:lower():find("flask") then
        is_python = true
        table.insert(output, "[!] X-Powered-By: " .. powered)
    end

    local err_response = http.get(host.ip, port, "/nonexistent_page_12345")
    if err_response and err_response.body then
        if err_response.body:find("Django") then
            is_python = true
            table.insert(output, "[!] Django debug page detected")
        end
        if err_response.body:find("Traceback") and err_response.body:find("File \"") then
            is_python = true
            table.insert(output, "[!] Python traceback exposed in error page")
        end
        if err_response.body:find("jinja2") or err_response.body:find("Jinja") then
            is_python = true
            table.insert(output, "[!] Jinja2 template engine detected")
        end
        if err_response.body:find("werkzeug") then
            is_python = true
            table.insert(output, "[!] Werkzeug (Flask) debug server detected")
        end
    end

    if not is_python then
        table.insert(output, "[-] Python not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] Python disclosure aids framework-specific attack targeting")

    return stdnse.format_output(true, output)
end
