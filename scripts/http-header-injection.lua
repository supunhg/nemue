-- HTTP Header Injection Detection
-- Tests for HTTP header injection vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for HTTP header injection (response splitting) vulnerabilities
by injecting CRLF sequences into parameters that affect response headers.
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
        {"%0d%0aInjected-Header: test", "Injected-Header"},
        {"%0aInjected-Header: test", "Injected-Header"},
        {"%0dInjected-Header: test", "Injected-Header"},
        {"test%0d%0aSet-Cookie: injected=true", "Set-Cookie.*injected"},
        {"test%0d%0aContent-Type: text/html", "Content-Type"},
    }

    local params = {"url", "redirect", "next", "return", "goto", "continue",
                    "ref", "target", "dest", "redir", "page", "link"}
    local test_paths = {"/", "/login.php", "/redirect.php"}

    for _, test_path in ipairs(test_paths) do
        for _, param in ipairs(params) do
            for _, payload in ipairs(payloads) do
                local url = test_path .. "?" .. param .. "=" .. payload[1]
                local r = http.get(host.ip, port, url, {redirect = false})
                if r then
                    local headers_str = ""
                    for k, v in pairs(r.header or {}) do
                        headers_str = headers_str .. k .. ": " .. v .. "\n"
                    end
                    if headers_str:find(payload[2]) then
                        table.insert(findings, {
                            url = test_path,
                            param = param,
                            payload = payload[1],
                            header = payload[2]
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
        table.insert(output, "Header Injection Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] URL: " .. f.url)
            table.insert(output, "[!]   Parameter: " .. f.param)
            table.insert(output, "[!]   Injected Header: " .. f.header)
            table.insert(output, "")
        end
        table.insert(output, "[!] HIGH: Allows response splitting and cache poisoning")
        return stdnse.format_output(true, output)
    end

    return nil
end
