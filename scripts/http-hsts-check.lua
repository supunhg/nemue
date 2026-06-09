local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Verifies HTTP Strict Transport Security (HSTS) header presence and
configuration including max-age, includeSubDomains, and preload directives.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "https" or port.number == 443)
end

action = function(host, port)
    local output = {}
    local issues = {}

    local response = http.get(host, port, "/")

    if not response or not response.header then
        return stdnse.format_output(false, "Could not retrieve HTTP response")
    end

    local hsts = response.header["strict-transport-security"]

    if not hsts then
        table.insert(issues, "CRITICAL: Missing HSTS header")
    else
        table.insert(output, "HSTS Header: " .. hsts)

        local max_age = hsts:match("max%-age=(%d+)")
        if max_age then
            local age = tonumber(max_age)
            if age < 31536000 then
                table.insert(issues, "Low max-age value: " .. max_age .. " seconds (recommended: 31536000)")
            else
                table.insert(output, "  max-age: " .. max_age .. " seconds (OK)")
            end
        else
            table.insert(issues, "Missing max-age directive")
        end

        if not hsts:lower():find("includesubdomains") then
            table.insert(issues, "Missing includeSubDomains directive")
        else
            table.insert(output, "  includeSubDomains: present")
        end

        if not hsts:lower():find("preload") then
            table.insert(issues, "Missing preload directive")
        else
            table.insert(output, "  preload: present")
        end
    end

    if #issues > 0 then
        table.insert(output, "\nHSTS Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
