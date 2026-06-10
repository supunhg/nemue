-- Code Injection Detection
-- Tests for code injection vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for code injection vulnerabilities including PHP, Python,
Ruby, and JavaScript code injection through web parameters.
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
        {";phpinfo();//", "PHP Version", "PHP code injection"},
        {"<?php echo 'INJECTED'; ?>", "INJECTED", "PHP code injection"},
        {"${7*7}", "49", "Expression evaluation"},
        {"{{7*7}}", "49", "Template expression evaluation"},
        {"<%= 7*7 %>", "49", "ERB template injection"},
        {"#set($x=7*7)${x}", "49", "Velocity template injection"},
    }

    local params = {"input", "data", "text", "content", "msg", "message", "q", "search"}
    local test_paths = {"/index.php", "/search.php", "/process.php"}

    for _, test_path in ipairs(test_paths) do
        for _, param in ipairs(params) do
            for _, payload in ipairs(payloads) do
                local url = test_path .. "?" .. param .. "=" .. payload[1]
                local r = http.get(host.ip, port, url)
                if r and r.body then
                    if r.body:find(payload[2]) then
                        table.insert(findings, {
                            url = url,
                            param = param,
                            payload = payload[1],
                            type = payload[3]
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
        table.insert(output, "Code Injection Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] URL: " .. f.url)
            table.insert(output, "[!]   Parameter: " .. f.param)
            table.insert(output, "[!]   Type: " .. f.type)
            table.insert(output, "[!]   Payload: " .. f.payload)
            table.insert(output, "")
        end
        table.insert(output, "[!] CRITICAL: Allows arbitrary code execution")
        return stdnse.format_output(true, output)
    end

    return nil
end
