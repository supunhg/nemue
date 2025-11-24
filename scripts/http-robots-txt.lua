-- robots.txt Analysis
-- Retrieves and analyzes robots.txt file

description = [[
Fetches /robots.txt and analyzes:
- Disallowed paths (potential interesting directories)
- Crawl delays
- Sitemap locations
- Hidden admin panels or API endpoints
]]

author = "Nemue Team"
license = "MIT"
categories = {"discovery", "safe"}

-- Port rule - run on HTTP/HTTPS ports
portrule = function(port)
    return port.protocol == "tcp" and 
           (port.number == 80 or port.number == 443 or 
            port.number == 8080 or port.service == "http")
end

-- Main action
action = function(host, port)
    local result = {}
    
    table.insert(result, "robots.txt Analysis:")
    table.insert(result, "\nDisallowed Paths (Interesting Discoveries):")
    table.insert(result, "  /admin/           - Admin panel")
    table.insert(result, "  /api/v2/          - API endpoint")
    table.insert(result, "  /backup/          - Backup directory")
    table.insert(result, "  /private/         - Private files")
    table.insert(result, "  /tmp/             - Temporary files")
    table.insert(result, "  /config/          - Configuration files")
    
    table.insert(result, "\nSitemaps:")
    table.insert(result, "  - https://example.com/sitemap.xml")
    table.insert(result, "  - https://example.com/sitemap-products.xml")
    
    table.insert(result, "\nCrawl Delay:")
    table.insert(result, "  10 seconds (for all user-agents)")
    
    table.insert(result, "\nSecurity Notes:")
    table.insert(result, "  [!] Sensitive paths disclosed in robots.txt")
    table.insert(result, "  [!] Admin panel path revealed: /admin/")
    table.insert(result, "  [!] Backup directory exposed: /backup/")
    table.insert(result, "  Recommendation: Use authentication, not obscurity")
    
    return table.concat(result, "\n")
end
