local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks if HTTP connections are properly redirected to HTTPS,
verifying the security of the redirect mechanism.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.number == 80 or port.number == 8080)
end

action = function(host, port)
    local output = {}
    local issues = {}

    local response = http.get(host, port, "/")

    if not response then
        return stdnse.format_output(false, "Could not connect to HTTP service")
    end

    if response.status >= 300 and response.status < 400 then
        local location = response.header["location"]
        if not location then
            table.insert(issues, "Redirect response missing Location header")
        else
            if not location:lower():find("^https://") then
                table.insert(issues, "Redirects to non-HTTPS URL: " .. location)
            else
                table.insert(output, "Proper HTTPS redirect detected: " .. location)
            end

            if response.status ~= 301 and response.status ~= 308 then
                table.insert(issues, "Using temporary redirect (" .. response.status .. ") instead of permanent (301)")
            end
        end
    elseif response.status == 200 then
        table.insert(issues, "No redirect - HTTP serves content directly")
    end

    if #issues > 0 then
        table.insert(output, "SSL Redirect Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
