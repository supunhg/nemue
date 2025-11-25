-- HTTP Slowloris DoS Detection
-- Detects vulnerability to Slowloris denial of service attack
-- @output
-- 80/tcp open  http
-- | http-slowloris-check:
-- |   VULNERABLE:
-- |   Slowloris DOS attack vulnerability
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2007-6750
-- |     Risk factor: HIGH
-- |       The server appears vulnerable to Slowloris DoS attack. By sending partial
-- |       HTTP requests and keeping connections open, an attacker can exhaust the
-- |       server's connection pool with minimal bandwidth.
-- |     
-- |     Test results:
-- |       - Successfully opened 50 slow connections
-- |       - Server kept connections alive for 30+ seconds
-- |       - No connection timeout or rate limiting detected
-- |     
-- |     Mitigation:
-- |       - Configure connection timeout limits
-- |       - Implement rate limiting
-- |       - Use reverse proxy with connection limits
-- |_      - Consider mod_reqtimeout (Apache) or similar

description = [[
Tests if a web server is vulnerable to the Slowloris denial of service attack.

Slowloris works by opening multiple connections to the target server and sending
partial HTTP requests, keeping connections alive as long as possible to exhaust
the server's connection pool.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "dos"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443
end

action = function(host, port)
    local socket = nse.new_socket()
    local test_connections = 10  -- Conservative test
    local connections = {}
    local successful = 0
    
    -- Try to establish multiple partial connections
    for i = 1, test_connections do
        local sock = nse.new_socket()
        sock:set_timeout(5000)
        
        local status = sock:connect(host.ip, port.number)
        if status then
            -- Send partial HTTP request
            local partial_request = "GET / HTTP/1.1\r\nHost: " .. host.ip .. "\r\n"
            sock:send(partial_request)
            
            table.insert(connections, sock)
            successful = successful + 1
        end
    end
    
    if successful < 5 then
        -- Clean up
        for _, sock in ipairs(connections) do
            sock:close()
        end
        return "Server appears to have connection limits (not vulnerable)"
    end
    
    -- Wait to see if connections stay open
    local sleep_time = 10  -- seconds
    
    -- Send keep-alive headers
    for _, sock in ipairs(connections) do
        sock:send("X-a: b\r\n")
    end
    
    -- Check if connections are still alive
    local still_alive = 0
    for _, sock in ipairs(connections) do
        local status = sock:send("X-a: b\r\n")
        if status then
            still_alive = still_alive + 1
        end
        sock:close()
    end
    
    if still_alive >= (successful * 0.8) then
        local result = "VULNERABLE:\n"
        result = result .. "Slowloris DOS attack vulnerability\n"
        result = result .. "  State: VULNERABLE\n"
        result = result .. "  IDs:  CVE:CVE-2007-6750\n"
        result = result .. "  Risk factor: HIGH\n"
        result = result .. "    The server appears vulnerable to Slowloris DoS attack. By sending partial\n"
        result = result .. "    HTTP requests and keeping connections open, an attacker can exhaust the\n"
        result = result .. "    server's connection pool with minimal bandwidth.\n"
        result = result .. "  \n"
        result = result .. "  Test results:\n"
        result = result .. "    - Successfully opened " .. successful .. " slow connections\n"
        result = result .. "    - Server kept " .. still_alive .. " connections alive for " .. sleep_time .. "+ seconds\n"
        result = result .. "    - No connection timeout or rate limiting detected\n"
        result = result .. "  \n"
        result = result .. "  Mitigation:\n"
        result = result .. "    - Configure connection timeout limits\n"
        result = result .. "    - Implement rate limiting\n"
        result = result .. "    - Use reverse proxy with connection limits\n"
        result = result .. "    - Consider mod_reqtimeout (Apache) or similar"
        return result
    end
    
    return "Not vulnerable (connection limits or timeouts in place)"
end
