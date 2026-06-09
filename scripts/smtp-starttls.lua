local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[
Checks SMTP server for STARTTLS support and verifies the
encryption capabilities of the mail server.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.number == 25 or port.number == 465 or port.number == 587 or
            port.service == "smtp")
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

    local response
    status, response = socket:receive_lines(1)
    if not status then
        socket:close()
        return stdnse.format_output(false, "No SMTP banner received")
    end

    table.insert(output, "SMTP STARTTLS Check:")
    table.insert(output, "  Banner: " .. response:gsub("\r?\n$", ""))

    socket:send("EHLO test.local\r\n")
    local ehlo_response = ""
    while true do
        status, response = socket:receive_lines(1)
        if not status then break end
        ehlo_response = ehlo_response .. response
        if response:match("^250 ") then break end
    end

    local has_starttls = ehlo_response:upper():find("STARTTLS")

    if has_starttls then
        table.insert(output, "  STARTTLS: Supported")

        socket:send("STARTTLS\r\n")
        status, response = socket:receive_lines(1)
        if status and response:match("^220") then
            table.insert(output, "  STARTTLS: Ready for TLS upgrade")
        else
            table.insert(issues, "STARTTLS advertised but failed")
        end
    else
        table.insert(issues, "STARTTLS not supported - emails sent in cleartext")
    end

    socket:close()

    local auth_methods = ehlo_response:match("AUTH ([^\r\n]+)")
    if auth_methods then
        table.insert(output, "  Auth Methods: " .. auth_methods)
        if auth_methods:upper():find("PLAIN") then
            table.insert(issues, "AUTH PLAIN supported (sends credentials in cleartext without TLS)")
        end
    end

    if #issues > 0 then
        table.insert(output, "\nIssues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    return stdnse.format_output(true, output)
end
