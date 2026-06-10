-- Server-Side Template Injection Detection
-- Tests for SSTI vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for Server-Side Template Injection (SSTI) vulnerabilities
by injecting template expressions into web application parameters.
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
        {"{{7*7}}", "49", "Jinja2/Twig"},
        {"${7*7}", "49", "FreeMarker/Velocity"},
        {"<%= 7*7 %>", "49", "ERB"},
        {"#{7*7}", "49", "Slim/Pug"},
        {"{{config}}", "SECRET", "Jinja2 config leak"},
        {"{{self.__class__.__mro__}}", "object", "Jinja2 MRO"},
        {"*{7*7}", "49", "Thymeleaf"},
    }

    local params = {"name", "template", "page", "view", "text", "input",
                    "content", "title", "body", "message"}
    local test_paths = {"/", "/index.php", "/render", "/preview", "/template"}

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
                            engine = payload[3]
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
        table.insert(output, "Server-Side Template Injection Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] URL: " .. f.url)
            table.insert(output, "[!]   Parameter: " .. f.param)
            table.insert(output, "[!]   Engine: " .. f.engine)
            table.insert(output, "[!]   Payload: " .. f.payload)
            table.insert(output, "")
        end
        table.insert(output, "[!] CRITICAL: Allows remote code execution via template injection")
        return stdnse.format_output(true, output)
    end

    return nil
end
