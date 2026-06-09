-- SSL DROWN Vulnerability Detection (CVE-2016-0800)
-- Tests for SSLv2 DROWN vulnerability
-- @output
-- 443/tcp open  https
-- | ssl-drown:
-- |   VULNERABLE:
-- |   SSL DROWN decryption vulnerability (CVE-2016-0800)
-- |     State: VULNERABLE
-- |     IDs:  CVE:CVE-2016-0800
-- |     Risk factor: HIGH  CVSSv3: 7.4 (HIGH) (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)
-- |       The SSLv2 protocol contains a vulnerability that allows attackers to
-- |       decrypt TLS connections by exploiting Bleichenbacher RSA padding oracle.
-- |       This is known as the DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) attack.
-- |     
-- |     Disclosure date: 2016-03-01
-- |     References:
-- |       https://drownattack.com/
-- |_      https://www.openssl.org/news/secadv/20160301.txt

description = [[
Tests whether a server supports SSLv2 and is vulnerable to the DROWN attack
(CVE-2016-0800). The vulnerability allows attackers to decrypt secure TLS connections.

The script attempts an SSLv2 handshake and checks if the server accepts it.
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
    
    -- Send SSLv2 Client Hello
    local client_hello = build_sslv2_client_hello()
    status, err = socket:send(client_hello)
    if not status then
        socket:close()
        return nil
    end
    
    -- Receive Server Response
    local status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return "SSLv2 not supported (not vulnerable)"
    end
    
    -- Check if server accepted SSLv2
    if #response > 2 then
        -- SSLv2 response starts with 0x80 (high bit set) followed by length
        local first_byte = string.byte(response, 1)
        
        if first_byte >= 0x80 then
            -- Check for SSLv2 Server Hello (0x04)
            local msg_type = string.byte(response, 3)
            
            if msg_type == 0x04 then  -- Server Hello
                local result = "VULNERABLE:\n"
                result = result .. "SSL DROWN decryption vulnerability (CVE-2016-0800)\n"
                result = result .. "  State: VULNERABLE\n"
                result = result .. "  IDs:  CVE:CVE-2016-0800\n"
                result = result .. "  Risk factor: HIGH  CVSSv3: 7.4 (HIGH) (AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)\n"
                result = result .. "    The SSLv2 protocol contains a vulnerability that allows attackers to\n"
                result = result .. "    decrypt TLS connections by exploiting Bleichenbacher RSA padding oracle.\n"
                result = result .. "    This is known as the DROWN (Decrypting RSA with Obsolete and Weakened eNcryption) attack.\n"
                result = result .. "  \n"
                result = result .. "  Disclosure date: 2016-03-01\n"
                result = result .. "  References:\n"
                result = result .. "    https://drownattack.com/\n"
                result = result .. "    https://www.openssl.org/news/secadv/20160301.txt"
                return result
            end
        end
    end
    
    return "Not vulnerable (SSLv2 disabled)"
end

-- Build SSLv2 Client Hello
function build_sslv2_client_hello()
    -- SSLv2 Client Hello format:
    -- Byte 0: 0x80 (high bit set for SSLv2)
    -- Byte 1: Length (2 bytes, big-endian)
    -- Byte 3: 0x01 (Client Hello)
    -- Byte 4-5: 0x0002 (Version SSL 2.0)
    -- Cipher specs length (2 bytes)
    -- Session ID length (2 bytes)
    -- Challenge length (2 bytes)
    -- Cipher specs
    -- Challenge
    
    local cipher_specs = {
        0x000005,  -- RC4 128 with MD5
        0x000004,  -- RC4 128 export with MD5
        0x000064,  -- RC2 128 CBC with MD5
        0x000062,  -- RC2 128 CBC export with MD5
        0x000003,  -- DES 64 CBC with MD5
        0x000006,  -- DES 192 EDE3 CBC with MD5
        0x000014,  -- DES 64 CBC with SHA
        0x000012,  -- DES 192 EDE3 CBC with SHA
        0x0000ff,  -- No cipher
    }
    
    -- Build cipher specs bytes
    local cipher_bytes = ""
    for _, cipher in ipairs(cipher_specs) do
        cipher_bytes = cipher_bytes .. string.char(
            bit.rshift(cipher, 16),
            bit.band(bit.rshift(cipher, 8), 0xff),
            bit.band(cipher, 0xff)
        )
    end
    
    -- Build challenge (16 bytes random)
    local challenge = ""
    for i = 1, 16 do
        challenge = challenge .. string.char(math.random(0, 255))
    end
    
    -- Lengths
    local cipher_len = #cipher_bytes
    local session_len = 0
    local challenge_len = #challenge
    
    -- Total data length
    local data_len = 9 + cipher_len + session_len + challenge_len
    
    -- Build header
    local header = "\x80"  -- SSLv2 marker
    header = header .. string.char(bit.band(data_len, 0xff))  -- Length low byte
    header = header .. "\x01"  -- Client Hello
    header = header .. "\x00\x02"  -- Version SSL 2.0
    header = header .. string.char(bit.rshift(cipher_len, 8), bit.band(cipher_len, 0xff))  -- Cipher specs length
    header = header .. string.char(bit.rshift(session_len, 8), bit.band(session_len, 0xff))  -- Session ID length
    header = header .. string.char(bit.rshift(challenge_len, 8), bit.band(challenge_len, 0xff))  -- Challenge length
    
    return header .. cipher_bytes .. challenge
end