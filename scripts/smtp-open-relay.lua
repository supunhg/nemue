-- SMTP Open Relay Test
-- Tests if SMTP server is an open relay

local nmap = require("nmap")
local stdnse = require("stdnse")
local smtp = require("smtp")

description = [[
Tests if an SMTP server is configured as an open relay by
attempting to send email to an external domain.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 25 or port.number == 587 or port.service == "smtp")
end

action = function(host, port)
    local output = {}
    local is_relay = false

    local socket = nmap.new_socket()
    local status, err = socket:connect(host, port)

    if not status then
        return stdnse.format_output(false, "Could not connect: " .. err)
    end

    local banner
    status, banner = socket:receive_lines(1)
    if status and banner then
        table.insert(output, "SMTP Banner: " .. banner)
    end

    socket:send("EHLO test.local\r\n")
    local ehlo_resp
    status, ehlo_resp = socket:receive_lines(1)

    socket:send("MAIL FROM:<test@test.com>\r\n")
    local mail_resp
    status, mail_resp = socket:receive_lines(1)

    if status and mail_resp and mail_resp:sub(1, 3) == "250" then
        socket:send("RCPT TO:<test@external-domain.com>\r\n")
        local rcpt_resp
        status, rcpt_resp = socket:receive_lines(1)

        if status and rcpt_resp and rcpt_resp:sub(1, 3) == "250" then
            is_relay = true
            table.insert(output, "CRITICAL: Server accepts external relay")
            table.insert(output, "  Response: " .. rcpt_resp)
        else
            table.insert(output, "Server rejects external relay (secure)")
        end
    end

    socket:send("QUIT\r\n")
    socket:close()

    if is_relay then
        table.insert(output, "\n[!] Open relay detected - server can be abused for spam")
    end

    return stdnse.format_output(true, output)
end
