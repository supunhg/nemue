-- EternalBlue Detection (MS17-010)
-- Detects SMBv1 vulnerability CVE-2017-0144
-- @output
-- 445/tcp open  microsoft-ds
-- | smb-eternalblue:
-- |   VULNERABLE: EternalBlue (MS17-010)
-- |     SMBv1 exploit detected
-- |_    System likely missing security patch

description = [[
Detects Microsoft Windows SMBv1 vulnerability (MS17-010/EternalBlue).
This vulnerability allows remote code execution and was used in WannaCry
and NotPetya ransomware attacks.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "smb"}

portrule = function(host, port)
    return port.number == 445 or port.service == "microsoft-ds"
end

action = function(host, port)
    local smb = require "smb"
    local vulns = {}

    local status, smbstate = smb.start(host, port)
    if not status then
        return "Could not connect to SMB service"
    end

    local status2, dialect = smb.negotiate_protocol(smbstate)
    if status2 and dialect then
        if dialect:find("SMB 1") or dialect:find("NT LM 0.12") then
            table.insert(vulns, "SMBv1 is enabled")
        end
    end

    local status3, shares = smb.share_get_list(smbstate)
    if status3 and shares then
        for _, share in ipairs(shares) do
            if share == "IPC$" then
                table.insert(vulns, "IPC$ share accessible")
                break
            end
        end
    end

    local status4, info = smb.get_os(smbstate)
    if status4 and info then
        if info:find("Windows") then
            if info:find("Windows 7") or info:find("Windows Server 2008") or
               info:find("Windows XP") or info:find("Windows Server 2003") then
                table.insert(vulns, "Potentially vulnerable OS: " .. info)
            end
        end
    end

    smb.stop(smbstate)

    if #vulns > 0 then
        local result = "VULNERABLE: EternalBlue (MS17-010)\n"
        result = result .. "  SMBv1 exploit indicators detected\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "Not vulnerable to EternalBlue"
end
