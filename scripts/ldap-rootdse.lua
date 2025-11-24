-- LDAP RootDSE Information Disclosure
-- Retrieves information from LDAP RootDSE entry
-- @output
-- 389/tcp open  ldap
-- | ldap-rootdse:
-- |   Naming Contexts:
-- |     DC=example,DC=com
-- |   Supported LDAP Versions: 2, 3
-- |   Server Name: dc01.example.com
-- |_  DNS Hostname: dc01.example.com

description = [[
Attempts to retrieve information from the LDAP RootDSE entry, which provides
information about the LDAP server capabilities, naming contexts, and configuration.
This is often anonymously accessible.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe", "default"}

portrule = function(host, port)
    return port.number == 389 or port.number == 636 or 
           port.service == "ldap" or port.service == "ldaps"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status, err = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- LDAP Bind Request (anonymous)
    local bind_request = build_ldap_bind()
    status, err = socket:send(bind_request)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    if not status then
        socket:close()
        return nil
    end
    
    -- Search RootDSE
    local search_request = build_ldap_search_rootdse()
    status, err = socket:send(search_request)
    if not status then
        socket:close()
        return nil
    end
    
    status, response = socket:receive()
    socket:close()
    
    if not status or not response then
        return nil
    end
    
    -- Parse response
    local results = {}
    
    -- Look for common RootDSE attributes
    if response:find("namingContexts") then
        table.insert(results, "Naming Contexts:")
        local contexts = extract_ldap_values(response, "namingContexts")
        for _, ctx in ipairs(contexts) do
            table.insert(results, "  " .. ctx)
        end
    end
    
    if response:find("supportedLDAPVersion") then
        local versions = extract_ldap_values(response, "supportedLDAPVersion")
        table.insert(results, "Supported LDAP Versions: " .. table.concat(versions, ", "))
    end
    
    if response:find("dnsHostName") then
        local hostnames = extract_ldap_values(response, "dnsHostName")
        if #hostnames > 0 then
            table.insert(results, "DNS Hostname: " .. hostnames[1])
        end
    end
    
    if response:find("serverName") then
        local names = extract_ldap_values(response, "serverName")
        if #names > 0 then
            table.insert(results, "Server Name: " .. names[1])
        end
    end
    
    if response:find("defaultNamingContext") then
        local contexts = extract_ldap_values(response, "defaultNamingContext")
        if #contexts > 0 then
            table.insert(results, "Default Naming Context: " .. contexts[1])
        end
    end
    
    if #results > 0 then
        return table.concat(results, "\n")
    end
    
    return "Anonymous LDAP access denied"
end

-- Build LDAP anonymous bind request
function build_ldap_bind()
    -- Simplified LDAP bind (anonymous)
    return "\x30\x0c\x02\x01\x01\x60\x07\x02\x01\x03\x04\x00\x80\x00"
end

-- Build LDAP search request for RootDSE
function build_ldap_search_rootdse()
    -- Simplified LDAP search with baseObject="" and scope=base
    return "\x30\x2a\x02\x01\x02\x63\x25\x04\x00\x0a\x01\x00\x0a" ..
           "\x01\x00\x02\x01\x00\x02\x01\x00\x01\x01\x00\xa0\x10" ..
           "\x87\x0e\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73"
end

-- Extract LDAP attribute values (simplified)
function extract_ldap_values(response, attribute)
    local values = {}
    -- Simplified extraction - look for printable strings after attribute name
    local pattern = attribute .. ".*?([\x20-\x7e]+)"
    for value in response:gmatch(pattern) do
        if #value > 2 then
            table.insert(values, value)
        end
    end
    return values
end
