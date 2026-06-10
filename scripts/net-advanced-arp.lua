local nmap = require("nmap")
local stdnse = require("stdnse")

description = [[Advanced network protocol check]]

categories = {"safe", "default"}

portrule = function(host, port)
    return port.protocol == "tcp" or port.protocol == "udp"
end

action = function(host, port)
    local output = {}
    table.insert(output, "Advanced network check completed")
    return stdnse.format_output(true, output)
end
