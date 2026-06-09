local nmap = require("nmap")
local stdnse = require("stdnse")
local bin = require("bin")

description = [[
Tests if MongoDB allows unauthenticated access by attempting
to list databases and server status without credentials.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 27017 or port.service == "mongodb")
end

local function build_mongo_msg(request_id, op_code, payload)
    local length = 16 + #payload
    return bin.pack("IIII", length, request_id, 0, op_code) .. payload
end

local function build_list_databases()
    local doc = "\x00\x00\x00\x00" ..
        "\x01listDatabases\x00\x00\x00\x00\x00\x00\x00\xf0?" ..
        "\x00"
    return build_mongo_msg(1, 2004, doc)
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

    status = socket:send(build_list_databases())
    if not status then
        socket:close()
        return stdnse.format_output(false, "Failed to send MongoDB request")
    end

    local response
    status, response = socket:receive_bytes(4096)
    socket:close()

    if not status or not response then
        return stdnse.format_output(false, "No MongoDB response received")
    end

    table.insert(output, "MongoDB Unauthenticated Access Check:")

    if #response > 16 then
        if response:find("databases") or response:find("totalSize") then
            table.insert(output, "  [!] CRITICAL: Unauthenticated access allowed")
            table.insert(issues, "MongoDB accepts unauthenticated connections")
            table.insert(output, "  Database listing may be accessible")
        elseif response:find("errmsg") or response:find("not allowed") then
            table.insert(output, "  Authentication required (OK)")
        else
            table.insert(output, "  Response received but format unknown")
        end
    else
        table.insert(output, "  No valid response (may require authentication)")
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Enable authentication in mongod.conf")
    table.insert(output, "  - Set bindIp to specific interfaces")
    table.insert(output, "  - Use firewall rules to restrict access")

    if #issues > 0 then
        table.insert(output, "\nSecurity Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
