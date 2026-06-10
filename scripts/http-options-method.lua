local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks HTTP OPTIONS method to enumerate allowed methods and detect
potentially dangerous method permissions.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or port.number == 8080)
end

local dangerous_methods = {"PUT", "DELETE", "PATCH", "TRACE", "CONNECT"}

action = function(host, port)
    local output = {}
    local issues = {}

    local options = {
        header = {},
    }

    local response = http.generic_request(host, port, "OPTIONS", "/", options)

    if not response then
        return stdnse.format_output(false, "OPTIONS request failed")
    end

    table.insert(output, "HTTP OPTIONS Response:")
    table.insert(output, "  Status: " .. response.status)

    local allow = response.header["allow"]
    if allow then
        table.insert(output, "  Allowed Methods: " .. allow)

        for _, method in ipairs(dangerous_methods) do
            if allow:upper():find(method) then
                table.insert(issues, "Dangerous method allowed: " .. method)
            end
        end

        if allow:upper():find("TRACE") then
            table.insert(issues, "TRACE method enabled (XST risk)")
        end
    else
        table.insert(output, "  No Allow header returned")
    end

    local public = response.header["public"]
    if public then
        table.insert(output, "  Public Methods: " .. public)
    end

    if #issues > 0 then
        table.insert(output, "\nIssues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
