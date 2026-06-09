local nmap = require("nmap")
local stdnse = require("stdnse")
local ldap = require("ldap")

description = [[
Tests if LDAP server allows anonymous binds and enumerates
accessible information without authentication.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 389 or port.number == 636 or port.service == "ldap")
end

action = function(host, port)
    local output = {}
    local issues = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)

    local status, err = socket:connect(host, port)
    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local bind_request = ldap.encode({
        message_id = 1,
        protocolOp = "bindRequest",
        version = 3,
        name = "",
        authentication = "simple",
    })

    if not bind_request then
        socket:close()
        return stdnse.format_output(false, "Failed to encode LDAP bind request")
    end

    status = socket:send(bind_request)
    if not status then
        socket:close()
        return stdnse.format_output(false, "Failed to send bind request")
    end

    local response
    status, response = socket:receive()
    socket:close()

    if not status or not response then
        return stdnse.format_output(false, "No LDAP response received")
    end

    if response:find("success") then
        table.insert(output, "LDAP Anonymous Bind: ALLOWED")
        table.insert(issues, "CRITICAL: Anonymous LDAP bind permitted")
    else
        table.insert(output, "LDAP Anonymous Bind: Denied")
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Disable anonymous binds")
    table.insert(output, "  - Require authentication for all queries")
    table.insert(output, "  - Implement proper access controls")

    if #issues > 0 then
        table.insert(output, "\nSecurity Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
