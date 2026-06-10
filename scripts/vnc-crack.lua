-- VNC Password Attempt
-- Tests VNC servers with common/blank passwords

local nmap = require("nmap")
local stdnse = require("stdnse")
local vnc = require("vnc")

description = [[
Attempts to authenticate to VNC servers using common and blank
passwords. Reports successful authentications and weak credentials.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"brute", "intrusive"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 5900 or port.number == 5901 or
            port.service == "vnc")
end

local common_passwords = {
    "", "password", "vnc", "admin", "123456", "1234",
    "root", "test", "guest", "changeme", "default",
    "letmein", "welcome", "abc123", "master", "server",
}

action = function(host, port)
    local results = {}

    local socket = nmap.new_socket()
    socket:set_timeout(5000)
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local banner
    status, banner = socket:receive_lines(1)
    if not status then
        socket:close()
        return stdnse.format_output(false, "No VNC banner received")
    end

    table.insert(results, "VNC Banner: " .. banner)

    local version = banner:match("RFB (%d+%.%d+)")
    if version then
        table.insert(results, "Protocol version: " .. version)
    end

    socket:close()

    for _, pwd in ipairs(common_passwords) do
        local vnc_socket = nmap.new_socket()
        vnc_socket:set_timeout(5000)
        status, err = vnc_socket:connect(host, port)

        if not status then
            break
        end

        local handshake = vnc_socket:receive_lines(1)
        if not handshake then
            vnc_socket:close()
            break
        end

        vnc_socket:send("RFB 003.008\n")

        local auth_methods
        status, auth_methods = vnc_socket:receive()
        if not status then
            vnc_socket:close()
            break
        end

        if #auth_methods >= 2 then
            local num_auth = auth_methods:byte(2)
            local has_vnc_auth = false
            for i = 3, 2 + num_auth do
                if auth_methods:byte(i) == 2 then
                    has_vnc_auth = true
                    break
                end
            end

            if has_vnc_auth then
                vnc_socket:send(string.char(2))

                local challenge
                status, challenge = vnc_socket:receive()
                if status and challenge and #challenge >= 16 then
                    local response
                    if #pwd == 0 then
                        response = string.rep("\0", 16)
                    else
                        response = pwd .. string.rep("\0", 8)
                        response = response:sub(1, 8)
                        response = response .. response
                    end

                    vnc_socket:send(response)

                    local auth_result
                    status, auth_result = vnc_socket:receive()
                    if status and auth_result and #auth_result >= 8 then
                        local result_code = auth_result:byte(8)
                        if result_code == 0 then
                            table.insert(results, "WEAK PASSWORD: '" .. pwd .. "'")
                        end
                    end
                end
            end
        end

        vnc_socket:close()
    end

    if #results <= 1 then
        table.insert(results, "No weak passwords found")
    end

    return stdnse.format_output(true, results)
end
