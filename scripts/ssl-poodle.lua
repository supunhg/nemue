-- SSL POODLE Vulnerability Detection (CVE-2014-3566)
-- Tests for SSLv3 POODLE vulnerability
-- @output
-- 443/tcp open  https
-- | ssl-poodle:
-- |   VULNERABLE:
-- |   SSL POODLE information disclosure vulnerability (CVE-2014-3566)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2014-3566
-- |     Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:P/I:N/A:N)
-- |       The SSL protocol 3.0 contains a vulnerability that allows attackers to
-- |       decrypt ciphertext using a padding oracle attack. This is known as the
-- |       POODLE (Padding Oracle On Downgraded Legacy Encryption) attack.
-- |     
-- |     Disclosure date: 2014-10-14
-- |     References:
-- |       https://www.imperialviolet.org/2014/10/14/poodle.html
-- |_      https://www.openssl.org/~bodo/ssl-poodle.pdf

description = [[
Tests whether a server supports SSLv3 and is vulnerable to the POODLE attack
(CVE-2014-3566). The vulnerability allows attackers to decrypt secure connections.

The script attempts a SSLv3 handshake and checks if the server accepts it.
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
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Send SSLv3 Client Hello
    local client_hello = build_sslv3_client_hello()
    status, err = socket:send(client_hello)
    if not status then
        socket:close()
        return nil
    end
    
    -- Receive Server Response
    local status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return "SSLv3 not supported (not vulnerable)"
    end
    
    -- Check if server accepted SSLv3
    if #response > 5 then
        local content_type = string.byte(response, 1)
        local version_major = string.byte(response, 2)
        local version_minor = string.byte(response, 3)
        
        -- Check for SSLv3 (0x0300) in response
        if content_type == 0x16 and version_major == 0x03 and version_minor == 0x00 then
            local result = "VULNERABLE:\n"
            result = result .. "SSL POODLE information disclosure vulnerability (CVE-2014-3566)\n"
            result = result .. "  State: VULNERABLE\n"
            result = result .. "  IDs:  CVE:CVE-2014-3566\n"
            result = result .. "  Risk factor: Medium  CVSSv2: 4.3 (MEDIUM) (AV:N/AC:M/Au:N/C:P/I:N/A:N)\n"
            result = result .. "    The SSL protocol 3.0 contains a vulnerability that allows attackers to\n"
            result = result .. "    decrypt ciphertext using a padding oracle attack. This is known as the\n"
            result = result .. "    POODLE (Padding Oracle On Downgraded Legacy Encryption) attack.\n"
            result = result .. "  \n"
            result = result .. "  Disclosure date: 2014-10-14\n"
            result = result .. "  References:\n"
            result = result .. "    https://www.imperialviolet.org/2014/10/14/poodle.html\n"
            result = result .. "    https://www.openssl.org/~bodo/ssl-poodle.pdf"
            return result
        end
    end
    
    return "Not vulnerable (SSLv3 disabled)"
end

-- Build SSLv3 Client Hello
function build_sslv3_client_hello()
    -- TLS Record Layer
    local record = "\x16"        -- ContentType: Handshake
    record = record .. "\x03\x00"  -- Version: SSL 3.0
    record = record .. "\x00\x61"  -- Length: 97 bytes
    
    -- Handshake Protocol
    local handshake = "\x01"       -- HandshakeType: Client Hello
    handshake = handshake .. "\x00\x00\x5d"  -- Length: 93 bytes
    handshake = handshake .. "\x03\x00"      -- Version: SSL 3.0
    
    -- Random (32 bytes - timestamp + random)
    local timestamp = string.pack(">I4", os.time())
    local random = timestamp
    for i = 1, 28 do
        random = random .. string.char(math.random(0, 255))
    end
    handshake = handshake .. random
    
    -- Session ID (empty)
    handshake = handshake .. "\x00"
    
    -- Cipher Suites (common SSLv3 ciphers)
    handshake = handshake .. "\x00\x2c"  -- Length: 44 bytes (22 suites)
    handshake = handshake .. "\x00\x39\x00\x38\x00\x35\x00\x16"
    handshake = handshake .. "\x00\x13\x00\x0a\x00\x33\x00\x32"
    handshake = handshake .. "\x00\x2f\x00\x07\x00\x05\x00\x04"
    handshake = handshake .. "\x00\x15\x00\x12\x00\x09\x00\x14"
    handshake = handshake .. "\x00\x11\x00\x08\x00\x06\x00\x03"
    handshake = handshake .. "\x00\xff"
    
    -- Compression Methods
    handshake = handshake .. "\x01"      -- Length: 1
    handshake = handshake .. "\x00"      -- Method: NULL
    
    return record .. handshake
end
