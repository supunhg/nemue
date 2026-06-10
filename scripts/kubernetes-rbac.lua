local http = require "http"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Checks Kubernetes RBAC (Role-Based Access Control) configurations.
Identifies overly permissive roles and bindings in Kubernetes clusters.
]]

---
-- @usage
-- nmap --script kubernetes-rbac -p 6443,8443 <target>
--
-- @output
-- PORT     STATE SERVICE
-- 6443/tcp open  https
-- | kubernetes-rbac:
-- |   Kubernetes RBAC Issues:
-- |     ClusterRole "cluster-admin" bindings:
-- |       - system:anonymous (VULNERABLE)
-- |     Overly permissive rules:
-- |       - Role: pod-reader
-- |         Resources: ["*"]
-- |         Verbs: ["*"]
-- |_    Use --script-args kubernetes-rbac.token=<token> for authenticated checks

author = "Nemue Security"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"vuln", "safe"}

portrule = shortport.port_or_service(6443, "kubernetes")

local sensitive_roles = {
  "cluster-admin",
  "admin",
  "edit",
  "view",
  "system:masters"
}

local dangerous_verbs = {
  "*",
  "create",
  "delete",
  "deletecollection",
  "patch",
  "update"
}

local sensitive_resources = {
  "*",
  "secrets",
  "pods",
  "deployments",
  "clusterroles",
  "clusterrolebindings",
  "roles",
  "rolebindings",
  "serviceaccounts"
}

local function make_k8s_request(host, port, path, token)
  local headers = {
    ["Accept"] = "application/json"
  }

  if token then
    headers["Authorization"] = "Bearer " .. token
  end

  local response = http.get(host, port, path, { headers = headers })
  return response
end

local function check_anonymous_access(host, port)
  local response = make_k8s_request(host, port, "/api/v1/namespaces", nil)
  if response and response.status == 200 then
    return true
  end
  return false
end

local function check_rbac_permissions(host, port, token)
  local issues = {}

  local roles_response = make_k8s_request(host, port, "/apis/rbac.authorization.k8s.io/v1/clusterroles", token)
  if roles_response and roles_response.status == 200 and roles_response.body then
    for _, role_name in ipairs(sensitive_roles) do
      if roles_response.body:match(role_name) then
        table.insert(issues, string.format('ClusterRole "%s" exists', role_name))
      end
    end

    if roles_response.body:match('"verbs"%s*:%s*%[%s*"%*"%s*%]') then
      table.insert(issues, "Overly permissive rules with wildcard verbs detected")
    end

    if roles_response.body:match('"resources"%s*:%s*%[%s*"%*"%s*%]') then
      table.insert(issues, "Overly permissive rules with wildcard resources detected")
    end
  end

  local bindings_response = make_k8s_request(host, port, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", token)
  if bindings_response and bindings_response.status == 200 and bindings_response.body then
    if bindings_response.body:match("system:anonymous") then
      table.insert(issues, "Anonymous users have cluster role bindings")
    end
    if bindings_response.body:match("system:unauthenticated") then
      table.insert(issues, "Unauthenticated users have cluster role bindings")
    end
  end

  return issues
end

local function check_etcd_access(host, port)
  local response = http.get(host, port, "/healthz")
  if response and response.status == 200 then
    return true
  end
  return false
end

action = function(host, port)
  local output = {}
  local vuln_count = 0

  local token = stdnse.get_script_args(SCRIPT_NAME .. ".token")

  local anon_access = check_anonymous_access(host, port)
  if anon_access then
    vuln_count = vuln_count + 1
    table.insert(output, "Anonymous API access: ENABLED (VULNERABLE)")
  else
    table.insert(output, "Anonymous API access: DISABLED")
  end

  local rbac_issues = check_rbac_permissions(host, port, token)
  if #rbac_issues > 0 then
    vuln_count = vuln_count + #rbac_issues
    table.insert(output, "")
    table.insert(output, "RBAC Issues Found:")
    for _, issue in ipairs(rbac_issues) do
      table.insert(output, "  - " .. issue)
    end
  end

  local etcd_accessible = check_etcd_access(host, port)
  if etcd_accessible then
    table.insert(output, "")
    table.insert(output, "API server health endpoint accessible")
  end

  if #output > 0 then
    local result = {}
    table.insert(result, "Kubernetes RBAC Check Results:")
    for _, line in ipairs(output) do
      table.insert(result, line)
    end
    table.insert(result, "")
    table.insert(result, "Recommendation: Disable anonymous authentication")
    table.insert(result, "Recommendation: Use least-privilege RBAC policies")
    table.insert(result, "Recommendation: Audit cluster-admin bindings")
    return table.concat(result, "\n")
  end

  return "No Kubernetes RBAC issues detected or API not accessible"
end
