-- Web Backdoor Detection
-- Scans for common web backdoors and shells

local http = require("http")
local stdnse = require("stdnse")

description = [[
Scans for common web backdoors, shells, and malicious PHP/JSP/ASP files
by testing known paths and analyzing responses for backdoor indicators.
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

    local backdoors = {
        {"/c99.php", "C99 Shell"},
        {"/r57.php", "R57 Shell"},
        {"/shell.php", "Web Shell"},
        {"/cmd.php", "Command Shell"},
        {"/b374k.php", "b374k Shell"},
        {"/b374k-mini.php", "b374k Mini Shell"},
        {"/wso.php", "WSO Shell"},
        {"/webshell.php", "Web Shell"},
        {"/backdoor.php", "Backdoor"},
        {"/hack.php", "Hack Tool"},
        {"/1337.php", "Hacker Tool"},
        {"/lol.php", "Shell"},
        {"/test-backdoor.php", "Test Backdoor"},
        {"/.well-known/shell.php", "Hidden Shell"},
        {"/uploads/shell.php", "Uploaded Shell"},
        {"/images/shell.php", "Hidden in Images"},
        {"/shell.jsp", "JSP Shell"},
        {"/cmd.jsp", "JSP Command Shell"},
        {"/backdoor.jsp", "JSP Backdoor"},
        {"/shell.aspx", "ASPX Shell"},
        {"/cmd.aspx", "ASPX Command Shell"},
        {"/shell.asp", "ASP Shell"},
    }

    for _, bd in ipairs(backdoors) do
        local r = http.get(host.ip, port, bd[1])
        if r and r.status == 200 and r.body then
            local body_lower = r.body:lower()
            if body_lower:find("shell") or body_lower:find("command") or
               body_lower:find("exec") or body_lower:find("system%(") or
               body_lower:find("passthru") or body_lower:find("eval%(") then
                table.insert(findings, bd[1] .. " - " .. bd[2])
            end
        end
    end

    if #findings > 0 then
        table.insert(output, "Web Backdoors Found:")
        table.insert(output, "")
        for _, f in ipairs(findings) do
            table.insert(output, "[!] " .. f)
        end
        table.insert(output, "")
        table.insert(output, "[!] CRITICAL: Web shells allow remote code execution")
        return stdnse.format_output(true, output)
    end

    return nil
end
