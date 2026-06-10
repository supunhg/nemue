-- SMB Signing Detection
-- Checks if SMB signing is enforced
-- @output
-- 445/tcp open  microsoft-ds
-- | smb-signing:
-- |   WARNING: SMB signing not enforced
-- |     Server does not require signing
-- |_    Vulnerable to relay attacks

description = [[
Checks if SMB signing is enforced on the target.
Without signing enforcement, systems are vulnerable to NTLM relay attacks.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default", "smb"}

portrule = function(host, port)
    return port.number == 445 or port.service == "microsoft-ds"
end

action = function(host, port)
    local smb = require "smb"
    local output = {}

    local status, smbstate = smb.start(host, port)
    if not status then
        return "Could not connect to SMB service"
    end

    local status2, security = smb.negotiate_security(smbstate)
    if status2 and security then
        if security.signing then
            table.insert(output, "SMB signing is enabled")
            if security.required then
                table.insert(output, "SMB signing is REQUIRED (secure)")
            else
                table.insert(output, "WARNING: SMB signing is enabled but NOT required")
                table.insert(output, "  Systems may be vulnerable to relay attacks")
            end
        else
            table.insert(output, "WARNING: SMB signing is DISABLED")
            table.insert(output, "  Vulnerable to NTLM relay attacks")
            table.insert(output, "  Recommendation: Enable and require SMB signing")
        end
    end

    local status3, info = smb.get_os(smbstate)
    if status3 and info then
        table.insert(output, "OS: " .. info)
    end

    smb.stop(smbstate)

    return stdnse.format_output(true, output)
end
