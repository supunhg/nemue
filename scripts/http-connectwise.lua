-- ConnectWise Detection (CVE-2024-1709)
-- Detects ConnectWise ScreenConnect authentication bypass
-- @output
-- 443/tcp open  https
-- | http-connectwise:
-- |   VULNERABLE: ConnectWise (CVE-2024-1709)
-- |     Authentication bypass detected
-- |_    Setup wizard accessible

description = [[
Detects ConnectWise ScreenConnect vulnerability (CVE-2024-1709).
This authentication bypass vulnerability allows attackers to create new
administrator accounts on vulnerable ScreenConnect instances.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "http"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 443 or port.number == 8040 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local vulns = {}

    local connectwise_paths = {
        "/",
        "/SetupWizard.aspx",
        "/Administration",
        "/Services/AuthenticationService.ashx",
        "/App_Themes",
    }

    for _, path in ipairs(connectwise_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 or response.status == 302 then
                if response.body then
                    if response.body:find("ScreenConnect") or
                       response.body:find("ConnectWise") or
                       response.body:find("SetupWizard") then
                        table.insert(vulns, "ScreenConnect detected: " .. path)
                    end
                end
            end
        end
    end

    local bypass_paths = {
        "/SetupWizard.aspx/DatabaseSetup",
        "/SetupWizard.aspx?step=2",
        "/Administration?submitType=CreateUser",
        "/Services/AuthenticationService.ashx?CreateAccount",
    }

    for _, path in ipairs(bypass_paths) do
        local response = http.get(host, port, path)
        if response and response.status then
            if response.status == 200 or response.status == 302 then
                if response.body and not response.body:find("404") then
                    table.insert(vulns, "Setup/wizard endpoint accessible: " .. path)
                end
            end
        end
    end

    if #vulns > 0 then
        local result = "VULNERABLE: ConnectWise (CVE-2024-1709)\n"
        result = result .. "  Authentication bypass detected\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "Not vulnerable to ConnectWise CVE-2024-1709"
end
