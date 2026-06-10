-- SMTP User Enumeration
-- Enumerates valid users via SMTP VRFY and RCPT TO commands

local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Attempts to enumerate valid users on an SMTP server using the
VRFY and RCPT TO commands. Tests a list of common usernames
and reports which ones the server confirms as valid.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"auth", "intrusive"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 25 or port.number == 465 or port.number == 587 or
            port.service == "smtp")
end

local common_users = {
    "root", "admin", "administrator", "user", "test", "guest",
    "info", "mail", "postmaster", "webmaster", "support",
    "sales", "hr", "help", "noreply", "backup", "operator",
    "www", "ftp", "nobody", "mysql", "apache", "nginx",
}

local function read_response(socket)
    local response = ""
    while true do
        local status, line = socket:receive_lines(1)
        if not status then return nil end
        response = response .. line .. "\n"
        if not line:match("^%d%d%d%-") then
            break
        end
    end
    return response
end

action = function(host, port)
    local results = {}
    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local banner = read_response(socket)
    if not banner then
        socket:close()
        return stdnse.format_output(false, "No banner received")
    end

    table.insert(results, "SMTP Banner: " .. banner:gsub("\n", " "))

    socket:send("EHLO nemue.scan\r\n")
    local ehlo = read_response(socket)
    if not ehlo then
        socket:close()
        return stdnse.format_output(false, "EHLO failed")
    end

    local vrfy_supported = true
    local vrfy_results = {}
    local rcpt_results = {}

    for _, user in ipairs(common_users) do
        socket:send("VRFY " .. user .. "\r\n")
        local resp = read_response(socket)
        if resp then
            local code = resp:match("^(%d%d%d)")
            if code == "250" or code == "252" then
                table.insert(vrfy_results, user .. " - valid")
            elseif code == "550" or code == "551" or code == "553" then
                -- user not found
            elseif code == "502" or code == "504" then
                vrfy_supported = false
                break
            end
        end
    end

    if vrfy_supported and #vrfy_results > 0 then
        table.insert(results, "\nVRFY enumeration results:")
        for _, r in ipairs(vrfy_results) do
            table.insert(results, "  " .. r)
        end
    end

    if not vrfy_supported then
        table.insert(results, "VRFY not supported, trying RCPT TO...")

        for _, user in ipairs(common_users) do
            socket:send("MAIL FROM:<test@test.com>\r\n")
            local mailfrom = read_response(socket)
            if not mailfrom then break end

            socket:send("RCPT TO:<" .. user .. "@test.com>\r\n")
            local rcpt = read_response(socket)
            if rcpt then
                local code = rcpt:match("^(%d%d%d)")
                if code == "250" or code == "251" then
                    table.insert(rcpt_results, user .. " - accepted")
                end
            end

            socket:send("RSET\r\n")
            read_response(socket)
        end

        if #rcpt_results > 0 then
            table.insert(results, "\nRCPT TO enumeration results:")
            for _, r in ipairs(rcpt_results) do
                table.insert(results, "  " .. r)
            end
        end
    end

    socket:send("QUIT\r\n")
    socket:close()

    if #results == 0 then
        return nil
    end

    return stdnse.format_output(true, results)
end
