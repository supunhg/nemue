-- HTTP GraphQL Introspection
-- Attempts GraphQL introspection queries to enumerate schema

local nmap = require("nmap")
local stdnse = require("stdnse")
local http = require("http")
local json = require("json")

description = [[
Sends GraphQL introspection queries to discover the schema,
types, queries, and mutations available on a GraphQL endpoint.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"discovery", "safe"}

portrule = function(host, port)
    return port.protocol == "tcp" and
           (port.service == "http" or port.service == "https" or
            port.number == 80 or port.number == 443 or
            port.number == 8080 or port.number == 8443)
end

local graphql_paths = {
    "/graphql", "/api/graphql", "/v1/graphql",
    "/query", "/api/query", "/gql",
    "/graphiql", "/graphql/console",
}

local introspection_query = [[{
  "query": "{ __schema { queryType { name } mutationType { name } subscriptionType { name } types { name kind description fields { name type { name kind ofType { name kind } } } } } }"
}]]

action = function(host, port)
    local results = {}

    for _, path in ipairs(graphql_paths) do
        local response = http.post(host, port, path, {
            header = { ["Content-Type"] = "application/json" },
            content = introspection_query
        })

        if response and response.status == 200 and response.body then
            local status, parsed = json.parse(response.body)
            if status and parsed and parsed.data and parsed.data.__schema then
                local schema = parsed.data.__schema
                table.insert(results, "GraphQL endpoint found: " .. path)

                if schema.queryType then
                    table.insert(results, "  Query type: " .. (schema.queryType.name or "N/A"))
                end
                if schema.mutationType then
                    table.insert(results, "  Mutation type: " .. (schema.mutationType.name or "N/A"))
                end
                if schema.subscriptionType then
                    table.insert(results, "  Subscription type: " .. (schema.subscriptionType.name or "N/A"))
                end

                if schema.types then
                    local user_types = {}
                    for _, t in ipairs(schema.types) do
                        if t.name and not t.name:match("^__") then
                            table.insert(user_types, t.name)
                        end
                    end
                    if #user_types > 0 then
                        table.insert(results, "  User-defined types: " .. table.concat(user_types, ", "))
                    end
                end

                break
            end
        end
    end

    if #results == 0 then
        return nil
    end

    return stdnse.format_output(true, results)
end
