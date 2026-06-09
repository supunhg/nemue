local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")

description = [[
Checks for AWS EC2 metadata service exposure (169.254.169.254)
which could lead to credential theft via SSRF vulnerabilities.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or port.number == 8080)
end

action = function(host, port)
    local output = {}
    local issues = {}

    local metadata_paths = {
        "/latest/meta-data/",
        "/latest/meta-data/instance-id",
        "/latest/meta-data/ami-id",
        "/latest/meta-data/hostname",
        "/latest/meta-data/iam/security-credentials/",
        "/latest/user-data",
    }

    local found_metadata = false

    for _, path in ipairs(metadata_paths) do
        local options = {
            header = {
                ["X-aws-ec2-metadata-token"] = "",
            },
        }

        local response = http.get(host, port, path)

        if response and response.status == 200 then
            if not found_metadata then
                table.insert(output, "AWS Metadata Service Check:")
                found_metadata = true
            end

            if path:find("security%-credentials") then
                table.insert(issues, "CRITICAL: IAM credentials endpoint accessible")
                table.insert(output, "  " .. path .. ": ACCESSIBLE")
            elseif path:find("user%-data") then
                table.insert(issues, "User-data endpoint accessible (may contain secrets)")
                table.insert(output, "  " .. path .. ": ACCESSIBLE")
            else
                table.insert(output, "  " .. path .. ": ACCESSIBLE")
            end
        end
    end

    if not found_metadata then
        table.insert(output, "No AWS metadata endpoints accessible from this host")
        table.insert(output, "Note: This check is most useful when run against")
        table.insert(output, "web applications that may be vulnerable to SSRF")
    end

    if #issues > 0 then
        table.insert(output, "\nSecurity Issues:")
        for _, issue in ipairs(issues) do
            table.insert(output, "  " .. issue)
        end
    end

    table.insert(output, "\nRecommendations:")
    table.insert(output, "  - Use IMDSv2 (token-required)")
    table.insert(output, "  - Block metadata access in application code")
    table.insert(output, "  - Use firewall rules to restrict 169.254.169.254")

    return stdnse.format_output(true, output)
end
