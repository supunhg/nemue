-- File Upload Endpoint Detection
-- Identifies file upload functionality on web applications

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Scans for file upload endpoints by checking common paths
and analyzing forms for file input fields.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "web"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

action = function(host, port)
    local output = {}
    local uploads_found = 0

    local paths = {
        "/", "/upload", "/upload.php", "/upload.asp", "/upload.aspx",
        "/admin/upload", "/file/upload", "/api/upload", "/api/files",
        "/media/upload", "/image/upload", "/document/upload",
        "/attachments", "/files", "/import", "/export"
    }

    table.insert(output, "Scanning for file upload endpoints")
    table.insert(output, "")

    for _, path in ipairs(paths) do
        local response = http.get(host.ip, port, path)

        if response and response.status == 200 then
            local body = response.body or ""

            if body:find('type="file"') or
               body:find('enctype="multipart/form%-data"') or
               body:find("multipart/form-data") or
               body:find("fileUpload") or
               body:find("uploadFile") then
                uploads_found = uploads_found + 1
                table.insert(output, "[!] Upload form found: " .. path)

                if body:find('accept="') then
                    local accept = body:match('accept="([^"]*)"')
                    if accept then
                        table.insert(output, "    File type filter: " .. accept)
                    end
                end
            end
        end
    end

    table.insert(output, "")
    if uploads_found > 0 then
        table.insert(output, "[!] Found " .. uploads_found .. " upload endpoints")
        table.insert(output, "[!] Test for unrestricted file upload vulnerabilities")
    else
        table.insert(output, "[+] No obvious upload endpoints found")
    end

    return stdnse.format_output(true, output)
end
