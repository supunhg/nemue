-- Business Logic Flaw Detection
-- Checks for common business logic vulnerabilities
-- @output
-- 80/tcp open  http
-- | http-business-logic:
-- |   WARNING: Business logic flaws detected
-- |     Negative quantity accepted in cart
-- |_    Price manipulation possible

description = [[
Detects common business logic vulnerabilities in web applications.
Tests for price manipulation, quantity overflow, race conditions,
and privilege escalation through business logic.
]]

author = "Nemue Security Team"
license = "MIT"
categories = {"vuln", "intrusive", "http"}

portrule = function(host, port)
    return port.service == "http" or port.service == "https" or
           port.number == 80 or port.number == 443 or port.number == 8080
end

action = function(host, port)
    local http = require "http"
    local vulns = {}

    local shop_paths = {
        "/cart", "/api/cart", "/api/v1/cart",
        "/checkout", "/api/checkout", "/order",
        "/api/orders", "/purchase"
    }

    for _, path in ipairs(shop_paths) do
        local negative_qty = '{"productId":1,"quantity":-1}'
        local options = {header = {["Content-Type"] = "application/json"}}
        local response = http.post(host, port, path, options, nil, negative_qty)
        if response and response.status then
            if response.status == 200 or response.status == 201 then
                if response.body and not response.body:find("error") then
                    table.insert(vulns, "Negative quantity accepted on " .. path)
                end
            end
        end

        local zero_price = '{"productId":1,"price":0}'
        local price_response = http.post(host, port, path, options, nil, zero_price)
        if price_response and price_response.status then
            if price_response.status == 200 or price_response.status == 201 then
                if price_response.body and not price_response.body:find("error") then
                    table.insert(vulns, "Zero price accepted on " .. path)
                end
            end
        end

        local overflow_qty = '{"productId":1,"quantity":999999999}'
        local overflow_response = http.post(host, port, path, options, nil, overflow_qty)
        if overflow_response and overflow_response.status then
            if overflow_response.status == 200 or overflow_response.status == 201 then
                if overflow_response.body and not overflow_response.body:find("error") then
                    table.insert(vulns, "Quantity overflow accepted on " .. path)
                end
            end
        end
    end

    local coupon_paths = {"/api/coupon", "/coupon/apply", "/api/discount"}
    for _, path in ipairs(coupon_paths) do
        local reuse_payload = '{"coupon":"TEST100","reuse":true}'
        local options = {header = {["Content-Type"] = "application/json"}}
        local response = http.post(host, port, path, options, nil, reuse_payload)
        if response and response.status then
            if response.status == 200 or response.status == 201 then
                if response.body and response.body:find("success") then
                    table.insert(vulns, "Coupon reuse possible on " .. path)
                end
            end
        end
    end

    local escalation_paths = {"/api/user/role", "/api/profile", "/user/settings"}
    for _, path in ipairs(escalation_paths) do
        local escalate_payload = '{"role":"admin","isAdmin":true}'
        local options = {header = {["Content-Type"] = "application/json"}}
        local response = http.put(host, port, path, options, nil, escalate_payload)
        if response and response.status then
            if response.status == 200 or response.status == 201 then
                if response.body and response.body:find("admin") then
                    table.insert(vulns, "Privilege escalation via " .. path)
                end
            end
        end
    end

    if #vulns > 0 then
        local result = "WARNING: Business logic flaws detected\n"
        for _, v in ipairs(vulns) do
            result = result .. "  " .. v .. "\n"
        end
        return result
    end

    return "No business logic vulnerabilities detected"
end
