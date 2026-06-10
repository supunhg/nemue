local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"

description = [[
Detects GraphQL endpoints and introspection.
]]

author = "Nemue"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"safe", "discovery"}

portrule = shortport.http

action = function(host, port)
  local result = {}
  local graphql_paths = {"/graphql", "/graphiql", "/api/graphql", "/v1/graphql"}

  for _, path in ipairs(graphql_paths) do
    local response = http.get(host, port, path)
    if response and response.status == 200 then
      table.insert(result, "GraphQL endpoint found: " .. path)
    end
  end

  local introspection_query = '{"query":"{__schema{queryType{name}}}"}'
  for _, path in ipairs(graphql_paths) do
    local response = http.post(host, port, path, {header = {["Content-Type"] = "application/json"}}, nil, introspection_query)
    if response and response.status == 200 and response.body and response.body:match("__schema") then
      table.insert(result, "Introspection enabled at: " .. path)
      table.insert(result, "WARNING: GraphQL introspection should be disabled in production")
    end
  end

  if #result == 0 then
    table.insert(result, "No GraphQL endpoints detected")
  end

  return stdnse.format_output(true, result)
end
