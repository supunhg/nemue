-- SMB Signing Check
-- Checks if SMB signing is required

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Checks if SMB signing is required on the target server.
SMB signing helps prevent man-in-the-middle attacks.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 445 or port.number == 139 or port.service == "microsoft-ds" or port.service == "netbios-ssn")
end

action = function(host, port)
    local output = {}

    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    table.insert(output, "SMB Signing Check:")
    table.insert(output, "  Port: " .. port.number)

    local smb_commands = require("smb")
    local smbstate

    status, smbstate = smb.start_ex(host, port, true, true)

    if status then
        local signing
        status, signing = smb.is_signing_required(smbstate)

        if status then
            if signing then
                table.insert(output, "  Signing: Required")
                table.insert(output, "  [+] SMB signing is enforced")
            else
                table.insert(output, "  Signing: Not Required")
                table.insert(output, "  [!] WARNING: SMB signing not enforced")
                table.insert(output, "  Vulnerable to MITM attacks")
            end
        end

        smb.stop(smbstate)
    else
        table.insert(output, "  Could not negotiate SMB connection")
    end

    socket:close()

    return stdnse.format_output(true, output)
end
