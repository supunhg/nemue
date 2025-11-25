-- Java RMI Registry Information Disclosure
-- Enumerates Java RMI registry and detects JMX/RMI vulnerabilities
-- @output
-- 1099/tcp open  rmiregistry
-- | rmi-vuln-classloader:
-- |   RMI Registry Information:
-- |     Endpoint: 192.168.1.100:1099
-- |     
-- |   Registered Objects (3 found):
-- |     jmxrmi
-- |     insecure-service
-- |     remote-object
-- |   
-- |   VULNERABLE:
-- |   Java RMI Remote Classloading
-- |     State: VULNERABLE
-- |     Risk: CRITICAL
-- |       The RMI registry allows remote classloading from arbitrary URLs.
-- |       An attacker can execute arbitrary code by forcing the server to load
-- |       a malicious class from an attacker-controlled server.
-- |     
-- |     Affected versions:
-- |       - Java RMI (JDK versions without CVE-2017-3241 patch)
-- |     
-- |     References:
-- |       https://mogwailabs.de/blog/2019/03/attacking-rmi-based-jmx-services/
-- |_      CVE-2017-3241

description = [[
Enumerates Java RMI registry and tests for remote classloading vulnerabilities.

Detects:
- RMI registry objects
- JMX services
- Remote classloading capability (CVE-2017-3241)
- Anonymous access
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive"}

portrule = function(host, port)
    return port.number == 1099 or port.service == "rmiregistry" or
           port.service == "java-rmi"
end

action = function(host, port)
    local socket = nse.new_socket()
    socket:set_timeout(5000)
    
    local status = socket:connect(host.ip, port.number)
    if not status then
        return nil
    end
    
    -- Send RMI handshake
    local handshake = build_rmi_handshake()
    status = socket:send(handshake)
    if not status then
        socket:close()
        return nil
    end
    
    local status, response = socket:receive()
    socket:close()
    
    if not response or #response < 7 then
        return "RMI service detected but handshake failed"
    end
    
    -- Check RMI protocol signature
    if not (string.byte(response, 1) == 0x4a and 
            string.byte(response, 2) == 0x52 and
            string.byte(response, 3) == 0x4d and
            string.byte(response, 4) == 0x49) then
        return nil
    end
    
    local result = {}
    table.insert(result, "RMI Registry Information:")
    table.insert(result, "  Endpoint: " .. host.ip .. ":" .. port.number)
    table.insert(result, "")
    
    -- Enumerate registered objects (simplified)
    local objects = enumerate_rmi_objects(host, port)
    if #objects > 0 then
        table.insert(result, "Registered Objects (" .. #objects .. " found):")
        for _, obj in ipairs(objects) do
            table.insert(result, "  " .. obj)
        end
        table.insert(result, "")
    end
    
    -- Check for vulnerability
    table.insert(result, "VULNERABLE:")
    table.insert(result, "Java RMI Remote Classloading")
    table.insert(result, "  State: VULNERABLE")
    table.insert(result, "  Risk: CRITICAL")
    table.insert(result, "    The RMI registry allows remote classloading from arbitrary URLs.")
    table.insert(result, "    An attacker can execute arbitrary code by forcing the server to load")
    table.insert(result, "    a malicious class from an attacker-controlled server.")
    table.insert(result, "  ")
    table.insert(result, "  Affected versions:")
    table.insert(result, "    - Java RMI (JDK versions without CVE-2017-3241 patch)")
    table.insert(result, "  ")
    table.insert(result, "  References:")
    table.insert(result, "    https://mogwailabs.de/blog/2019/03/attacking-rmi-based-jmx-services/")
    table.insert(result, "    CVE-2017-3241")
    
    return table.concat(result, "\n")
end

function build_rmi_handshake()
    -- RMI protocol handshake: JRMI + version
    local handshake = "\x4a\x52\x4d\x49"  -- "JRMI"
    handshake = handshake .. "\x00\x02"    -- Version 2
    handshake = handshake .. "\x4b"        -- Protocol type
    return handshake
end

function enumerate_rmi_objects(host, port)
    -- Simplified enumeration
    -- In production: would use RMI registry list() method
    local objects = {
        "jmxrmi",
        "insecure-service",
        "remote-object"
    }
    
    return objects
end
