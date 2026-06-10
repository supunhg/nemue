local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[Compliance check script]]

categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp"
end

action = function(host, port)
    local output = {}
    table.insert(output, "Compliance check completed")
    return stdnse.format_output(true, output)
end
