// HTML/SVG interactive visualization for network topology
use crate::topology::{TopologyMap, DeviceInfo, DeviceType};

/// Visualization engine for network topology
pub struct VisualizationEngine;

impl VisualizationEngine {
    /// Generate HTML with D3.js interactive network map
    pub fn generate_html(map: &TopologyMap) -> String {
        let nodes_json = Self::nodes_to_json(map);
        let links_json = Self::links_to_json(map);
        let js_code = Self::get_d3_script(&nodes_json, &links_json);
        
        format!(
            concat!(
                "<!DOCTYPE html>\n",
                "<html lang=\"en\">\n",
                "<head>\n",
                "    <meta charset=\"UTF-8\">\n",
                "    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n",
                "    <title>Network Topology - Nemue</title>\n",
                "    <script src=\"https://d3js.org/d3.v7.min.js\"></script>\n",
                "    {}\n",
                "</head>\n",
                "<body>\n",
                "    <div id=\"info\">\n",
                "        <h3>Network Topology</h3>\n",
                "        <p>Target: {}</p>\n",
                "        <p>Devices: {}</p>\n",
                "        <p>Segments: {}</p>\n",
                "    </div>\n",
                "    {}\n",
                "    <div class=\"tooltip\" id=\"tooltip\"></div>\n",
                "    <svg id=\"topology\"></svg>\n",
                "    {}\n",
                "</body>\n",
                "</html>"
            ),
            Self::get_styles(),
            map.target,
            map.devices.len(),
            map.segments.len(),
            Self::get_legend(),
            js_code
        )
    }

    fn get_styles() -> &'static str {
        r#"<style>
        body {
            margin: 0;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #1a1a2e;
            color: #eee;
        }
        #topology {
            width: 100vw;
            height: 100vh;
        }
        .node {
            cursor: pointer;
            stroke: #fff;
            stroke-width: 2px;
        }
        .link {
            stroke: #999;
            stroke-opacity: 0.6;
            stroke-width: 2px;
        }
        .label {
            font-size: 12px;
            fill: #eee;
            pointer-events: none;
        }
        .tooltip {
            position: absolute;
            background: rgba(0, 0, 0, 0.9);
            color: #fff;
            padding: 10px;
            border-radius: 5px;
            pointer-events: none;
            display: none;
            font-size: 14px;
        }
        #info {
            position: absolute;
            top: 20px;
            right: 20px;
            background: rgba(0, 0, 0, 0.8);
            padding: 15px;
            border-radius: 8px;
            max-width: 300px;
        }
        .legend {
            position: absolute;
            bottom: 20px;
            left: 20px;
            background: rgba(0, 0, 0, 0.8);
            padding: 15px;
            border-radius: 8px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin: 5px 0;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            margin-right: 10px;
            border-radius: 3px;
        }
    </style>"#
    }

    fn get_legend() -> &'static str {
        r#"<div class="legend">
        <h4>Device Types</h4>
        <div class="legend-item">
            <div class="legend-color" style="background: #4a90e2;"></div>
            <span>Router</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #7cb342;"></div>
            <span>Switch</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #ff7043;"></div>
            <span>Firewall</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #fdd835;"></div>
            <span>Server</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #ab47bc;"></div>
            <span>Workstation</span>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background: #78909c;"></div>
            <span>Other</span>
        </div>
    </div>"#
    }

    fn get_d3_script(nodes_json: &str, links_json: &str) -> String {
        format!(
            r#"<script>
const nodesData = {};
const linksData = {};
const width = window.innerWidth;
const height = window.innerHeight;
const svg = d3.select('#topology').attr('width', width).attr('height', height);
const simulation = d3.forceSimulation(nodesData)
    .force('link', d3.forceLink(linksData).id(d => d.id).distance(150))
    .force('charge', d3.forceManyBody().strength(-500))
    .force('center', d3.forceCenter(width / 2, height / 2));
const link = svg.append('g').selectAll('line').data(linksData).enter().append('line').attr('class', 'link');
const node = svg.append('g').selectAll('circle').data(nodesData).enter().append('circle')
    .attr('class', 'node').attr('r', d => d.importance * 5 + 15).attr('fill', d => d.color);
simulation.on('tick', () => {{
    link.attr('x1', d => d.source.x).attr('y1', d => d.source.y).attr('x2', d => d.target.x).attr('y2', d => d.target.y);
    node.attr('cx', d => d.x).attr('cy', d => d.y);
}});
</script>"#,
            nodes_json,
            links_json
        )
    }

    /// Generate SVG topology diagram
    pub fn generate_svg(map: &TopologyMap) -> String {
        let mut svg = String::from(r#"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1200 800">"#);
        svg.push_str("\n  <style>");
        svg.push_str("\n    .device { stroke: #333; stroke-width: 2; }");
        svg.push_str("\n    .link { stroke: #999; stroke-width: 2; fill: none; }");
        svg.push_str("\n    .label { font-family: Arial; font-size: 12px; fill: #333; }");
        svg.push_str("\n  </style>\n");

        // Draw connections
        let y_pos = 100;
        for i in 0..map.path_to_target.len().saturating_sub(1) {
            let x1 = 100 + i * 200;
            let x2 = 100 + (i + 1) * 200;
            svg.push_str(&format!(
                "  <line class=\"link\" x1=\"{}\" y1=\"{}\" x2=\"{}\" y2=\"{}\"/>\n",
                x1, y_pos, x2, y_pos
            ));
        }

        // Draw devices
        for (idx, addr) in map.path_to_target.iter().enumerate() {
            let x = 100 + idx * 200;
            let device_info = map.devices.get(addr);
            let color = if let Some(info) = device_info {
                match info.device_type {
                    DeviceType::Router => "#4a90e2",
                    DeviceType::Switch => "#7cb342",
                    DeviceType::Firewall => "#ff7043",
                    DeviceType::Server => "#fdd835",
                    _ => "#78909c",
                }
            } else {
                "#cccccc"
            };

            svg.push_str(&format!(
                "  <circle class=\"device\" cx=\"{}\" cy=\"{}\" r=\"30\" fill=\"{}\"/>\n",
                x, y_pos, color
            ));
            svg.push_str(&format!(
                "  <text class=\"label\" x=\"{}\" y=\"{}\" text-anchor=\"middle\">{}</text>\n",
                x, y_pos + 50, addr
            ));
        }

        svg.push_str("</svg>");
        svg
    }

    fn nodes_to_json(map: &TopologyMap) -> String {
        let mut nodes = Vec::new();
        
        for (addr, info) in &map.devices {
            let color = match info.device_type {
                DeviceType::Router => "#4a90e2",
                DeviceType::Switch => "#7cb342",
                DeviceType::Firewall => "#ff7043",
                DeviceType::Server => "#fdd835",
                DeviceType::Workstation => "#ab47bc",
                _ => "#78909c",
            };
            
            let importance = Self::calculate_importance(info);
            
            nodes.push(format!(
                r#"{{"id": "{}", "label": "{}", "type": "{:?}", "color": "{}", "importance": {}, "os": {}, "hostname": {}}}"#,
                addr,
                addr,
                info.device_type,
                color,
                importance,
                info.os_family.as_ref().map(|s| format!("\"{}\"", s)).unwrap_or_else(|| "null".to_string()),
                info.hostname.as_ref().map(|s| format!("\"{}\"", s)).unwrap_or_else(|| "null".to_string())
            ));
        }
        
        format!("[{}]", nodes.join(", "))
    }

    fn links_to_json(map: &TopologyMap) -> String {
        let mut links = Vec::new();
        
        for i in 0..map.path_to_target.len().saturating_sub(1) {
            let source = &map.path_to_target[i];
            let target = &map.path_to_target[i + 1];
            links.push(format!(
                r#"{{"source": "{}", "target": "{}"}}"#,
                source, target
            ));
        }
        
        format!("[{}]", links.join(", "))
    }

    fn calculate_importance(info: &DeviceInfo) -> u8 {
        match info.device_type {
            DeviceType::Firewall => 5,
            DeviceType::Router => 4,
            DeviceType::Server => 4,
            DeviceType::Switch => 3,
            DeviceType::Workstation => 2,
            _ => 1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::net::IpAddr;
    use std::str::FromStr;

    #[test]
    fn test_generate_html() {
        let mut devices = HashMap::new();
        let router = IpAddr::from_str("192.168.1.1").unwrap();
        devices.insert(router, DeviceInfo {
            device_type: DeviceType::Router,
            os_family: Some("Cisco IOS".to_string()),
            vendor: Some("Cisco".to_string()),
            hostname: Some("gw1".to_string()),
        });

        let map = TopologyMap {
            target: IpAddr::from_str("8.8.8.8").unwrap(),
            segments: vec![],
            devices,
            path_to_target: vec![router],
        };

        let html = VisualizationEngine::generate_html(&map);
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Network Topology"));
        assert!(html.contains("d3.v7.min.js"));
        assert!(html.contains("8.8.8.8"));
    }

    #[test]
    fn test_generate_svg() {
        let mut devices = HashMap::new();
        let router = IpAddr::from_str("192.168.1.1").unwrap();
        devices.insert(router, DeviceInfo {
            device_type: DeviceType::Router,
            os_family: None,
            vendor: None,
            hostname: None,
        });

        let map = TopologyMap {
            target: IpAddr::from_str("8.8.8.8").unwrap(),
            segments: vec![],
            devices,
            path_to_target: vec![router],
        };

        let svg = VisualizationEngine::generate_svg(&map);
        assert!(svg.contains("<svg"));
        assert!(svg.contains("192.168.1.1"));
        assert!(svg.contains("#4a90e2")); // Router color
    }

    #[test]
    fn test_importance_calculation() {
        let firewall = DeviceInfo {
            device_type: DeviceType::Firewall,
            os_family: None,
            vendor: None,
            hostname: None,
        };
        assert_eq!(VisualizationEngine::calculate_importance(&firewall), 5);

        let workstation = DeviceInfo {
            device_type: DeviceType::Workstation,
            os_family: None,
            vendor: None,
            hostname: None,
        };
        assert_eq!(VisualizationEngine::calculate_importance(&workstation), 2);
    }
}
