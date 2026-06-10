-- Internal IP Disclosure
-- Detects internal IP addresses in HTTP responses

local http = require("http")
local stdnse = require("stdnse")
local string = require("string")

description = [[
Scans HTTP responses for internal/private IP address
disclosure in headers and page content.
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
    local disclosures = {}

    local response = http.get(host.ip, port, "/")

    if not response then
        return "No HTTP response received"
    end

    local ip_pattern = "(%d+)%.(%d+)%.(%d+)%.(%d+)"

    local function is_private(a, b, c, d)
        a, b, c, d = tonumber(a), tonumber(b), tonumber(c), tonumber(d)
        if a == 10 then return true end
        if a == 172 and b >= 16 and b <= 31 then return true end
        if a == 192 and b == 168 then return true end
        if a == 127 then return true end
        return false
    end

    if response.header then
        for name, value in pairs(response.header) do
            local ip = tostring(value):match(ip_pattern)
            if ip then
                local a, b, c, d = tostring(value):match(ip_pattern)
                if is_private(a, b, c, d) then
                    table.insert(disclosures, "Header " .. name .. ": " .. ip)
                end
            end
        end
    end

    local body = response.body or ""
    for ip in body:gmatch(ip_pattern) do
        local a, b, c, d = body:match("(" .. ip:gsub("%.", "%%.") .. ")")
        if a then
            local parts = {}
            for part in ip:gmatch("%d+") do
                table.insert(parts, tonumber(part))
            end
            if #parts == 4 and is_private(parts[1], parts[2], parts[3], parts[4]) then
                table.insert(disclosures, "Body content: " .. ip)
            end
        end
    end

    table.insert(output, "Internal IP Disclosure Scan")
    table.insert(output, "")

    if #disclosures > 0 then
        for _, disc in ipairs(disclosures) do
            table.insert(output, "[!] " .. disc)
        end
        table.insert(output, "")
        table.insert(output, "[!] Found " .. #disclosures .. " internal IP disclosures")
    else
        table.insert(output, "[+] No internal IP addresses disclosed")
    end

    return stdnse.format_output(true, output)
end
