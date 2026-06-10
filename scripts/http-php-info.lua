-- PHP Application Information Disclosure
-- Detects PHP version and configuration details

local http = require("http")
local stdnse = require("stdnse")

description = [[
Detects PHP information disclosure including version, modules,
and exposed phpinfo() pages through headers and common paths.
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
    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    table.insert(output, "PHP Application Information Disclosure")
    table.insert(output, "")

    local powered = response.header and response.header["x-powered-by"]
    local is_php = false

    if powered and powered:lower():find("php") then
        is_php = true
        table.insert(output, "[!] X-Powered-By: " .. powered)
        local version = powered:match("PHP/([%d%.]+)")
        if version then
            table.insert(output, "[!] PHP Version: " .. version)
        end
    end

    local paths = {
        {"/phpinfo.php", "phpinfo() page"},
        {"/info.php", "phpinfo() page"},
        {"/test.php", "Test PHP page"},
        {"/i.php", "phpinfo() page"},
        {"/pi.php", "phpinfo() page"},
    }

    for _, check in ipairs(paths) do
        local r = http.get(host.ip, port, check[1])
        if r and r.status == 200 and r.body and r.body:find("PHP Version") then
            is_php = true
            table.insert(output, "[!] " .. check[2] .. " accessible at " .. check[1])
            local version = r.body:match("PHP Version[^%d]*([%d%.]+)")
            if version then
                table.insert(output, "[!] PHP Version: " .. version)
            end
        end
    end

    if response.body and response.body:find("%.php") then
        is_php = true
        table.insert(output, "[!] PHP file references found in page")
    end

    if not is_php then
        table.insert(output, "[-] PHP not detected")
    end

    table.insert(output, "")
    table.insert(output, "[!] PHP disclosure aids version-specific exploit targeting")

    return stdnse.format_output(true, output)
end
