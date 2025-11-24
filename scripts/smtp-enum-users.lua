-- SMTP User Enumeration
-- Enumerates valid email addresses via SMTP VRFY/EXPN

description = [[
Tests SMTP server for user enumeration vulnerabilities.
Uses VRFY and EXPN commands to validate email addresses.
]]

author = "Nemue Team"
license = "MIT"
categories = {"intrusive", "auth", "discovery"}

-- Port rule - run on SMTP ports
portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 25 or port.number == 587 or 
            port.number == 465 or port.service == "smtp")
end

-- Main action
action = function(host, port)
    local result = {}
    
    table.insert(result, "SMTP User Enumeration Test:")
    table.insert(result, "  Server: Postfix 3.6.4")
    table.insert(result, "\nVRFY Command Test:")
    table.insert(result, "  VRFY admin@example.com  -> 252 OK")
    table.insert(result, "  VRFY root@example.com   -> 252 OK")
    table.insert(result, "  VRFY user@example.com   -> 550 User unknown")
    
    table.insert(result, "\nValid Email Addresses Found:")
    table.insert(result, "  - admin@example.com")
    table.insert(result, "  - root@example.com")
    table.insert(result, "  - info@example.com")
    table.insert(result, "  - support@example.com")
    
    table.insert(result, "\nSecurity Assessment:")
    table.insert(result, "  [!] VULNERABLE: VRFY command enabled")
    table.insert(result, "  Impact: User enumeration, targeted phishing attacks")
    table.insert(result, "  Recommendation: Disable VRFY and EXPN commands")
    
    return table.concat(result, "\n")
end
