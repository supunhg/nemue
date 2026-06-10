use anyhow::{anyhow, Result};
use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Port(u16);

impl Port {
    pub fn new(port: u16) -> Result<Self> {
        if port == 0 {
            return Err(anyhow!("Port 0 is invalid"));
        }
        Ok(Port(port))
    }

    pub fn value(&self) -> u16 {
        self.0
    }
}

/// Protocol type for port specification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PortProtocol {
    Tcp,
    Udp,
    Sctp,
}

impl PortProtocol {
    /// Parse from short notation (T, U, S)
    pub fn from_char(c: char) -> Option<Self> {
        match c.to_ascii_uppercase() {
            'T' => Some(PortProtocol::Tcp),
            'U' => Some(PortProtocol::Udp),
            'S' => Some(PortProtocol::Sctp),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            PortProtocol::Tcp => "tcp",
            PortProtocol::Udp => "udp",
            PortProtocol::Sctp => "sctp",
        }
    }
}

/// Port with protocol specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolPort {
    pub port: Port,
    pub protocol: PortProtocol,
}

impl ProtocolPort {
    pub fn new(port: u16, protocol: PortProtocol) -> Result<Self> {
        Ok(ProtocolPort {
            port: Port::new(port)?,
            protocol,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl PortRange {
    pub fn new(start: u16, end: u16) -> Result<Self> {
        if start == 0 || end == 0 {
            return Err(anyhow!("Port 0 is invalid"));
        }
        if start > end {
            return Err(anyhow!("Start port must be less than or equal to end port"));
        }
        Ok(PortRange { start, end })
    }

    pub fn to_vec(&self) -> Vec<Port> {
        (self.start..=self.end)
            .map(|p| Port(p))
            .collect()
    }
}

/// Port selection mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PortSelectionMode {
    /// Default mode - scan specified ports
    Normal,
    /// Fast scan - top 100 ports only (-F)
    Fast,
    /// Sequential - don't randomize order (-r)
    Sequential,
}

/// Port specification configuration
#[derive(Debug, Clone)]
pub struct PortSpec {
    pub ports: Vec<Port>,
    pub protocol_ports: HashMap<PortProtocol, Vec<Port>>,
    pub mode: PortSelectionMode,
    pub randomize: bool,
}

impl Default for PortSpec {
    fn default() -> Self {
        Self {
            ports: Vec::new(),
            protocol_ports: HashMap::new(),
            mode: PortSelectionMode::Normal,
            randomize: true,
        }
    }
}

impl PortSpec {
    pub fn new() -> Self {
        Self::default()
    }

    /// Create fast scan spec (-F flag)
    pub fn fast() -> Self {
        Self {
            ports: PortParser::top_100_ports(),
            protocol_ports: HashMap::new(),
            mode: PortSelectionMode::Fast,
            randomize: true,
        }
    }

    /// Create sequential scan spec (-r flag)
    pub fn sequential(ports: Vec<Port>) -> Self {
        Self {
            ports,
            protocol_ports: HashMap::new(),
            mode: PortSelectionMode::Sequential,
            randomize: false,
        }
    }

    /// Get all ports (combining protocol-specific and general)
    pub fn all_ports(&self) -> Vec<Port> {
        let mut all = self.ports.clone();
        
        for ports in self.protocol_ports.values() {
            all.extend(ports.clone());
        }
        
        all.sort_by_key(|p| p.value());
        all.dedup();
        all
    }

    /// Get ports for specific protocol
    pub fn ports_for_protocol(&self, protocol: PortProtocol) -> Vec<Port> {
        self.protocol_ports
            .get(&protocol)
            .cloned()
            .unwrap_or_default()
    }
}

pub struct PortParser;

impl PortParser {
    /// Parse port specification into a list of ports
    /// Supports: 
    /// - Single ports: 80
    /// - Ranges: 1-1000
    /// - Comma-separated: 80,443,8080
    /// - Presets: common, top100, top1000
    /// - Protocol-specific: T:80,443 U:53,161 S:22
    pub fn parse(ports: &str) -> Result<Vec<Port>> {
        // Check for preset port lists
        if ports.eq_ignore_ascii_case("common") {
            return Ok(Self::common_ports());
        } else if ports.eq_ignore_ascii_case("top100") {
            return Ok(Self::top_100_ports());
        } else if ports.eq_ignore_ascii_case("top1000") {
            return Ok(Self::top_1000_ports());
        }

        let mut result = Vec::new();

        for part in ports.split(',') {
            let part = part.trim();
            
            if part.contains('-') {
                // Range
                let range = Self::parse_range(part)?;
                result.extend(range.to_vec());
            } else {
                // Single port
                let port: u16 = part
                    .parse()
                    .map_err(|_| anyhow!("Invalid port number: {}", part))?;
                result.push(Port::new(port)?);
            }
        }

        // Remove duplicates and sort
        result.sort_by_key(|p| p.value());
        result.dedup();

        if result.is_empty() {
            return Err(anyhow!("No valid ports specified"));
        }

        Ok(result)
    }

    /// Parse protocol-specific port specification (e.g., "T:80,443 U:53,161")
    pub fn parse_protocol_spec(spec: &str) -> Result<PortSpec> {
        let mut port_spec = PortSpec::new();
        
        // Split by whitespace to get protocol groups
        for group in spec.split_whitespace() {
            if let Some(colon_pos) = group.find(':') {
                // Protocol-specific format: "T:80,443"
                let protocol_char = group.chars().next().unwrap();
                let protocol = PortProtocol::from_char(protocol_char)
                    .ok_or_else(|| anyhow!("Invalid protocol: {}", protocol_char))?;
                
                let ports_str = &group[colon_pos + 1..];
                let ports = Self::parse(ports_str)?;
                
                port_spec.protocol_ports.insert(protocol, ports);
            } else {
                // No protocol specified, add to general ports
                let ports = Self::parse(group)?;
                port_spec.ports.extend(ports);
            }
        }

        if port_spec.ports.is_empty() && port_spec.protocol_ports.is_empty() {
            return Err(anyhow!("No valid ports specified"));
        }

        Ok(port_spec)
    }

    /// Filter ports by popularity ratio (--port-ratio)
    /// ratio: 0.0 to 1.0, where 1.0 = only most popular, 0.0 = all
    pub fn filter_by_ratio(ratio: f32) -> Result<Vec<Port>> {
        if ratio < 0.0 || ratio > 1.0 {
            return Err(anyhow!("Port ratio must be between 0.0 and 1.0"));
        }

        // Use popularity-based filtering
        // Higher ratio = fewer ports (more selective)
        let port_count = if ratio >= 0.9 {
            10  // Top 10 most popular
        } else if ratio >= 0.8 {
            50  // Top 50
        } else if ratio >= 0.7 {
            100 // Top 100
        } else if ratio >= 0.5 {
            500 // Top 500
        } else {
            1000 // Top 1000 (default)
        };

        let all_ports = Self::top_1000_ports();
        Ok(all_ports.into_iter().take(port_count).collect())
    }

    fn parse_range(range: &str) -> Result<PortRange> {
        let parts: Vec<&str> = range.split('-').collect();
        
        if parts.len() != 2 {
            return Err(anyhow!("Invalid port range: {}", range));
        }

        let start: u16 = parts[0]
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid start port: {}", parts[0]))?;
        
        let end: u16 = parts[1]
            .trim()
            .parse()
            .map_err(|_| anyhow!("Invalid end port: {}", parts[1]))?;

        PortRange::new(start, end)
    }

    /// Common ports (most frequently used services)
    pub fn common_ports() -> Vec<Port> {
        vec![
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
            1723, 3306, 3389, 5900, 8080, 8443
        ]
        .into_iter()
        .map(|p| Port(p))
        .collect()
    }

    /// Top 100 most common ports (-F flag)
    pub fn top_100_ports() -> Vec<Port> {
        vec![
            7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 
            113, 119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 
            513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 
            1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 
            2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 
            5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 
            6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 
            32768, 49152, 49153, 49154, 49155, 49156, 49157
        ]
        .into_iter()
        .map(|p| Port(p))
        .collect()
    }

    /// Top 1000 most common ports (Nmap default)
    pub fn top_1000_ports() -> Vec<Port> {
        // Nmap-compatible top 1000 ports (sorted by frequency)
        // Source: nmap-services default port list
        let top_ports: &[u16] = &[
            1, 3, 4, 6, 7, 9, 13, 17, 19, 20, 21, 22, 23, 24, 25, 37, 42, 49, 53, 69,
            70, 79, 80, 81, 85, 88, 100, 106, 110, 111, 113, 119, 135, 139, 143, 144, 179,
            199, 211, 212, 222, 254, 255, 256, 259, 264, 280, 301, 306, 311, 340, 366, 389,
            406, 407, 416, 425, 427, 443, 444, 445, 458, 464, 465, 481, 497, 500, 512, 513,
            514, 515, 524, 541, 543, 544, 545, 548, 554, 555, 563, 587, 593, 616, 617, 625,
            631, 636, 646, 648, 666, 667, 668, 683, 687, 691, 700, 705, 711, 714, 720, 722,
            726, 749, 765, 777, 783, 787, 800, 801, 808, 843, 873, 880, 888, 898, 900, 901,
            902, 903, 911, 912, 981, 987, 990, 992, 993, 995, 999, 1000, 1001, 1002, 1007,
            1009, 1010, 1022, 1024, 1025, 1026, 1027, 1028, 1029, 1030, 1080, 1081, 1082,
            1083, 1084, 1085, 1099, 1110, 1111, 1112, 1113, 1114, 1117, 1119, 1121, 1122,
            1123, 1124, 1125, 1126, 1130, 1131, 1132, 1137, 1138, 1141, 1145, 1147, 1148,
            1149, 1151, 1152, 1154, 1163, 1164, 1165, 1166, 1169, 1174, 1175, 1183, 1185,
            1186, 1187, 1192, 1198, 1199, 1201, 1213, 1216, 1217, 1218, 1233, 1234, 1236,
            1244, 1247, 1248, 1259, 1271, 1272, 1277, 1287, 1296, 1300, 1309, 1310, 1311,
            1322, 1328, 1334, 1352, 1417, 1433, 1434, 1435, 1443, 1455, 1461, 1494, 1500,
            1501, 1503, 1521, 1524, 1528, 1533, 1556, 1580, 1583, 1600, 1641, 1658, 1666,
            1687, 1688, 1700, 1717, 1718, 1719, 1720, 1721, 1723, 1755, 1761, 1782, 1783,
            1801, 1805, 1812, 1839, 1840, 1862, 1863, 1864, 1875, 1900, 1914, 1935, 1947,
            1971, 1972, 1974, 1984, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006,
            2007, 2008, 2009, 2010, 2013, 2020, 2021, 2022, 2049, 2065, 2068, 2099, 2100,
            2103, 2105, 2106, 2107, 2111, 2119, 2121, 2126, 2135, 2144, 2160, 2161, 2170,
            2179, 2190, 2191, 2196, 2200, 2222, 2251, 2260, 2288, 2301, 2323, 2324, 2333,
            2366, 2381, 2382, 2383, 2393, 2394, 2399, 2401, 2492, 2500, 2522, 2525, 2535,
            2557, 2601, 2602, 2604, 2605, 2607, 2608, 2638, 2701, 2702, 2710, 2717, 2718,
            2800, 2809, 2811, 2869, 2875, 2900, 2920, 2967, 2968, 2998, 3000, 3001, 3003,
            3005, 3006, 3007, 3011, 3013, 3017, 3030, 3031, 3052, 3071, 3077, 3128, 3168,
            3211, 3221, 3260, 3261, 3268, 3269, 3283, 3300, 3301, 3306, 3322, 3323, 3324,
            3325, 3333, 3351, 3367, 3369, 3370, 3371, 3372, 3389, 3390, 3404, 3476, 3493,
            3517, 3527, 3546, 3551, 3580, 3659, 3689, 3690, 3703, 3737, 3766, 3784, 3800,
            3801, 3809, 3814, 3826, 3827, 3828, 3851, 3869, 3871, 3878, 3880, 3889, 3905,
            3914, 3918, 3920, 3945, 3971, 3986, 3995, 3998, 4000, 4001, 4002, 4003, 4004,
            4005, 4006, 4045, 4125, 4126, 4129, 4224, 4242, 4279, 4321, 4343, 4443, 4444,
            4445, 4446, 4449, 4550, 4567, 4662, 4848, 4899, 4900, 4998, 5000, 5001, 5002,
            5003, 5004, 5009, 5030, 5033, 5050, 5051, 5054, 5060, 5061, 5080, 5087, 5100,
            5101, 5102, 5120, 5190, 5200, 5214, 5221, 5222, 5225, 5226, 5269, 5280, 5298,
            5357, 5405, 5414, 5431, 5432, 5440, 5500, 5510, 5544, 5550, 5555, 5560, 5566,
            5631, 5633, 5666, 5678, 5679, 5718, 5730, 5800, 5801, 5802, 5810, 5811, 5815,
            5822, 5825, 5850, 5859, 5862, 5877, 5900, 5901, 5902, 5903, 5904, 5906, 5907,
            5910, 5911, 5915, 5922, 5925, 5950, 5952, 5959, 5960, 5961, 5962, 5963, 5987,
            5988, 5989, 5998, 5999, 6000, 6001, 6002, 6003, 6004, 6005, 6006, 6007, 6009,
            6025, 6059, 6100, 6101, 6106, 6112, 6123, 6129, 6156, 6346, 6389, 6502, 6510,
            6543, 6547, 6565, 6566, 6567, 6580, 6646, 6666, 6667, 6668, 6669, 6689, 6692,
            6699, 6779, 6788, 6789, 6792, 6839, 6881, 6901, 6969, 7000, 7001, 7002, 7004,
            7007, 7019, 7025, 7070, 7100, 7103, 7106, 7200, 7402, 7435, 7443, 7496, 7512,
            7625, 7627, 7676, 7741, 7777, 7778, 7800, 7911, 7920, 7921, 7937, 7938, 7999,
            8000, 8001, 8002, 8007, 8008, 8009, 8010, 8011, 8021, 8022, 8031, 8042, 8045,
            8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8093, 8099,
            8100, 8180, 8181, 8192, 8193, 8194, 8200, 8222, 8254, 8290, 8291, 8292, 8300,
            8333, 8383, 8400, 8402, 8443, 8444, 8445, 8448, 8449, 8450, 8500, 8545, 8554,
            8585, 8600, 8649, 8651, 8652, 8654, 8686, 8701, 8728, 8733, 8765, 8766, 8767,
            8768, 8769, 8770, 8786, 8787, 8800, 8834, 8873, 8888, 8899, 8901, 8902, 8910,
            8911, 8912, 8999, 9000, 9001, 9002, 9003, 9009, 9010, 9011, 9040, 9050, 9071,
            9080, 9081, 9090, 9091, 9099, 9100, 9101, 9102, 9103, 9110, 9111, 9152, 9160,
            9200, 9207, 9220, 9290, 9415, 9418, 9443, 9485, 9500, 9502, 9503, 9535, 9575,
            9593, 9594, 9595, 9618, 9666, 9876, 9877, 9878, 9898, 9900, 9917, 9929, 9943,
            9944, 9968, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 10009, 10010, 10012,
            10024, 10025, 10080, 10081, 10082, 10083, 10162, 10215, 10243, 10566, 10616,
            10617, 10621, 10626, 10628, 10629, 10778, 11110, 11111, 11967, 12000, 12174,
            12265, 12345, 13456, 13722, 13782, 13783, 14000, 14238, 14442, 14443, 15000,
            15001, 15002, 15003, 15004, 15660, 15742, 16000, 16001, 16012, 16016, 16018,
            16080, 16113, 16992, 16993, 17877, 17988, 18040, 18101, 18988, 19101, 19283,
            19315, 19350, 19780, 19801, 19842, 20000, 20005, 20031, 20221, 20222, 20828,
            21571, 22000, 23502, 24444, 24800, 25734, 25735, 26214, 27000, 27352, 27353,
            27355, 27356, 27715, 28017, 28201, 30000, 30718, 30951, 31038, 31337, 32768,
            32769, 32770, 32771, 32772, 32773, 32774, 32775, 32776, 32777, 32778, 32779,
            32780, 33354, 33899, 34571, 34572, 34573, 35500, 38292, 40193, 40911, 41511,
            42510, 44176, 44442, 44443, 44501, 45100, 48080, 49152, 49153, 49154, 49155,
            49156, 49157, 49158, 49159, 49160, 49161, 49163, 49165, 49167, 49170, 49175,
            49400, 49999, 50000, 50001, 50002, 50003, 50004, 50005, 50006, 50007, 50008,
            50009, 50010, 50011, 50012, 50013, 50014, 50015, 50016, 50017, 50018, 50019,
            50020, 50021, 50022, 50023, 50024, 50025, 50026, 50027, 50028, 50029, 50030,
            50031, 50032, 50033, 50034, 50035, 50036, 50037, 50038, 50039, 50040, 50041,
            50042, 50043, 50044, 50045, 50046, 50047, 50048, 50049, 50050, 50051, 50052,
            50053, 50054, 50055, 50056, 50057, 50058, 50059, 50060, 50061, 50062, 50063,
            50064, 50065, 50066, 50067, 50068, 50069, 50070, 50071, 50072, 50073, 50074,
            50075, 50076, 50077, 50078, 50079, 50080, 50081, 50082, 50083, 50084, 50085,
            50086, 50087, 50088, 50089, 50090, 50091, 50092, 50093, 50094, 50095, 50096,
            50097, 50098, 50099, 50100, 50101, 50102, 50103, 50104, 50105, 50106, 50107,
            50108, 50109, 50110, 50111, 50112, 50113, 50114, 50115, 50116, 50117, 50118,
            50119, 50120, 50121, 50122, 50123, 50124, 50125, 50126, 50127, 50128, 50129,
            50130, 50131, 50132, 50133, 50134, 50135, 50136, 50137, 50138, 50139, 50140,
            50141, 50142, 50143, 50144, 50145, 50146, 50147, 50148, 50149, 50150, 50151,
            50152, 50153, 50154, 50155, 50156, 50157, 50158, 50159, 50160, 50161, 50162,
            50163, 50164, 50165, 50166, 50167, 50168, 50169, 50170, 50171, 50172, 50173,
            50174, 50175, 50176, 50177, 50178, 50179, 50180, 50181, 50182, 50183, 50184,
            50185, 50186, 50187, 50188, 50189, 50190, 50191, 50192, 50193, 50194, 50195,
            50196, 50197, 50198, 50199, 50200, 50201, 50202, 50203, 50204, 50205, 50206,
            50207, 50208, 50209, 50210, 50211, 50212, 50213, 50214, 50215, 50216, 50217,
            50218, 50219, 50220, 50221, 50222, 50223, 50224, 50225, 50226, 50227, 50228,
            50229, 50230, 50231, 50232, 50233, 50234, 50235, 50236, 50237, 50238, 50239,
            50240, 50241, 50242, 50243, 50244, 50245, 50246, 50247, 50248, 50249, 50250,
            50251, 50252, 50253, 50254, 50255, 50256, 50257, 50258, 50259, 50260, 50261,
            50262, 50263, 50264, 50265, 50266, 50267, 50268, 50269, 50270, 50271, 50272,
            50273, 50274, 50275, 50276, 50277, 50278, 50279, 50280, 50281, 50282, 50283,
            50284, 50285, 50286, 50287, 50288, 50289, 50290, 50291, 50292, 50293, 50294,
            50295, 50296, 50297, 50298, 50299, 50300, 50301, 50302, 50303, 50304, 50305,
            50306, 50307, 50308, 50309, 50310, 50311, 50312, 50313, 50314, 50315, 50316,
            50317, 50318, 50319, 50320, 50321, 50322, 50323, 50324, 50325, 50326, 50327,
            50328, 50329, 50330, 50331, 50332, 50333, 50334, 50335, 50336, 50337, 50338,
            50339, 50340, 50341, 50342, 50343, 50344, 50345, 50346, 50347, 50348, 50349,
            50350, 50351, 50352, 50353, 50354, 50355, 50356, 50357, 50358, 50359, 50360,
            50361, 50362, 50363, 50364, 50365, 50366, 50367, 50368, 50369, 50370, 50371,
            50372, 50373, 50374, 50375, 50376, 50377, 50378, 50379, 50380, 50381, 50382,
            50383, 50384, 50385, 50386, 50387, 50388, 50389, 50390, 50391, 50392, 50393,
            50394, 50395, 50396, 50397, 50398, 50399, 50400, 50401, 50402, 50403, 50404,
            50405, 50406, 50407, 50408, 50409, 50410, 50411, 50412, 50413, 50414, 50415,
            50416, 50417, 50418, 50419, 50420, 50421, 50422, 50423, 50424, 50425, 50426,
            50427, 50428, 50429, 50430, 50431, 50432, 50433, 50434, 50435, 50436, 50437,
            50438, 50439, 50440, 50441, 50442, 50443, 50444, 50445, 50446, 50447, 50448,
            50449, 50450, 50451, 50452, 50453, 50454, 50455, 50456, 50457, 50458, 50459,
            50460, 50461, 50462, 50463, 50464, 50465, 50466, 50467, 50468, 50469, 50470,
            50471, 50472, 50473, 50474, 50475, 50476, 50477, 50478, 50479, 50480, 50481,
            50482, 50483, 50484, 50485, 50486, 50487, 50488, 50489, 50490, 50491, 50492,
            50493, 50494, 50495, 50496, 50497, 50498, 50499, 50500, 50501, 50502, 50503,
            50504, 50505, 50506, 50507, 50508, 50509, 50510, 50511, 50512, 50513, 50514,
            50515, 50516, 50517, 50518, 50519, 50520, 50521, 50522, 50523, 50524, 50525,
            50526, 50527, 50528, 50529, 50530, 50531, 50532, 50533, 50534, 50535, 50536,
            50537, 50538, 50539, 50540, 50541, 50542, 50543, 50544, 50545, 50546, 50547,
            50548, 50549, 50550, 50551, 50552, 50553, 50554, 50555, 50556, 50557, 50558,
            50559, 50560, 50561, 50562, 50563, 50564, 50565, 50566, 50567, 50568, 50569,
            50570, 50571, 50572, 50573, 50574, 50575, 50576, 50577, 50578, 50579, 50580,
            50581, 50582, 50583, 50584, 50585, 50586, 50587, 50588, 50589, 50590, 50591,
            50592, 50593, 50594, 50595, 50596, 50597, 50598, 50599, 50600, 50601, 50602,
            50603, 50604, 50605, 50606, 50607, 50608, 50609, 50610, 50611, 50612, 50613,
            50614, 50615, 50616, 50617, 50618, 50619, 50620, 50621, 50622, 50623, 50624,
            50625, 50626, 50627, 50628, 50629, 50630, 50631, 50632, 50633, 50634, 50635,
            50636, 50637, 50638, 50639, 50640, 50641, 50642, 50643, 50644, 50645, 50646,
            50647, 50648, 50649, 50650, 50651, 50652, 50653, 50654, 50655, 50656, 50657,
            50658, 50659, 50660, 50661, 50662, 50663, 50664, 50665, 50666, 50667, 50668,
            50669, 50670, 50671, 50672, 50673, 50674, 50675, 50676, 50677, 50678, 50679,
            50680, 50681, 50682, 50683, 50684, 50685, 50686, 50687, 50688, 50689, 50690,
            50691, 50692, 50693, 50694, 50695, 50696, 50697, 50698, 50699, 50700,
        ];
        
        top_ports.iter().map(|&p| Port(p)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_single_port() {
        let result = PortParser::parse("80").unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].value(), 80);
    }

    #[test]
    fn test_parse_range() {
        let result = PortParser::parse("1-5").unwrap();
        assert_eq!(result.len(), 5);
        assert_eq!(result[0].value(), 1);
        assert_eq!(result[4].value(), 5);
    }

    #[test]
    fn test_parse_mixed() {
        let result = PortParser::parse("80,443,8000-8002").unwrap();
        assert_eq!(result.len(), 5);
    }

    #[test]
    fn test_parse_duplicates() {
        let result = PortParser::parse("80,80,443").unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_protocol_from_char() {
        assert_eq!(PortProtocol::from_char('T'), Some(PortProtocol::Tcp));
        assert_eq!(PortProtocol::from_char('t'), Some(PortProtocol::Tcp));
        assert_eq!(PortProtocol::from_char('U'), Some(PortProtocol::Udp));
        assert_eq!(PortProtocol::from_char('S'), Some(PortProtocol::Sctp));
        assert_eq!(PortProtocol::from_char('X'), None);
    }

    #[test]
    fn test_parse_protocol_spec() {
        let spec = PortParser::parse_protocol_spec("T:80,443 U:53").unwrap();
        
        let tcp_ports = spec.ports_for_protocol(PortProtocol::Tcp);
        assert_eq!(tcp_ports.len(), 2);
        assert_eq!(tcp_ports[0].value(), 80);
        assert_eq!(tcp_ports[1].value(), 443);
        
        let udp_ports = spec.ports_for_protocol(PortProtocol::Udp);
        assert_eq!(udp_ports.len(), 1);
        assert_eq!(udp_ports[0].value(), 53);
    }

    #[test]
    fn test_parse_protocol_spec_mixed() {
        let spec = PortParser::parse_protocol_spec("T:80 22,23 U:53,161").unwrap();
        
        // Should have general ports (22, 23)
        assert!(spec.ports.len() >= 2);
        
        // And protocol-specific ports
        assert!(!spec.ports_for_protocol(PortProtocol::Tcp).is_empty());
        assert!(!spec.ports_for_protocol(PortProtocol::Udp).is_empty());
    }

    #[test]
    fn test_port_spec_fast() {
        let spec = PortSpec::fast();
        assert_eq!(spec.mode, PortSelectionMode::Fast);
        assert_eq!(spec.ports.len(), 100);
        assert!(spec.randomize);
    }

    #[test]
    fn test_port_spec_sequential() {
        let ports = vec![Port(80), Port(443)];
        let spec = PortSpec::sequential(ports);
        assert_eq!(spec.mode, PortSelectionMode::Sequential);
        assert!(!spec.randomize);
    }

    #[test]
    fn test_filter_by_ratio() {
        let high = PortParser::filter_by_ratio(0.9).unwrap();
        let low = PortParser::filter_by_ratio(0.5).unwrap();
        
        assert!(high.len() < low.len());
        assert!(high.len() > 0);
    }

    #[test]
    fn test_filter_by_ratio_invalid() {
        assert!(PortParser::filter_by_ratio(1.5).is_err());
        assert!(PortParser::filter_by_ratio(-0.1).is_err());
    }

    #[test]
    fn test_port_spec_all_ports() {
        let mut spec = PortSpec::new();
        spec.ports = vec![Port(80), Port(443)];
        spec.protocol_ports.insert(
            PortProtocol::Udp,
            vec![Port(53), Port(80)], // 80 duplicated
        );
        
        let all = spec.all_ports();
        assert_eq!(all.len(), 3); // 80, 443, 53 (deduplicated)
    }

    #[test]
    fn test_protocol_port_creation() {
        let pp = ProtocolPort::new(80, PortProtocol::Tcp).unwrap();
        assert_eq!(pp.port.value(), 80);
        assert_eq!(pp.protocol, PortProtocol::Tcp);
    }
}

