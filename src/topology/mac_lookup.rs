// MAC address vendor lookup and hardware identification
use lazy_static::lazy_static;
use std::collections::HashMap;

lazy_static! {
    #[allow(dead_code)]
    static ref OUI_DATABASE: HashMap<&'static str, &'static str> = {
        let mut db = HashMap::new();

        // Major networking vendors
        db.insert("00:00:0C", "Cisco Systems");
        db.insert("00:01:42", "Cisco Systems");
        db.insert("00:01:43", "Cisco Systems");
        db.insert("00:1B:D5", "Cisco Systems");
        db.insert("00:50:56", "VMware");
        db.insert("00:0C:29", "VMware");
        db.insert("00:05:69", "VMware");
        db.insert("00:1C:14", "VMware");
        db.insert("00:50:73", "Intel Corporation");
        db.insert("00:1B:21", "Intel Corporation");
        db.insert("00:1E:67", "Intel Corporation");
        db.insert("00:15:5D", "Microsoft Corporation");
        db.insert("00:03:FF", "Microsoft Corporation");
        db.insert("00:17:FA", "Microsoft Corporation");

        // HP/HPE
        db.insert("00:11:0A", "Hewlett Packard");
        db.insert("00:1F:29", "Hewlett Packard");
        db.insert("00:21:5A", "Hewlett Packard");
        db.insert("00:23:7D", "Hewlett Packard");

        // Dell
        db.insert("00:14:22", "Dell Inc.");
        db.insert("00:1C:23", "Dell Inc.");
        db.insert("00:21:70", "Dell Inc.");
        db.insert("00:26:B9", "Dell Inc.");

        // Apple
        db.insert("00:03:93", "Apple Inc.");
        db.insert("00:0A:95", "Apple Inc.");
        db.insert("00:17:F2", "Apple Inc.");
        db.insert("00:1B:63", "Apple Inc.");
        db.insert("00:1E:C2", "Apple Inc.");
        db.insert("00:23:12", "Apple Inc.");
        db.insert("00:25:00", "Apple Inc.");

        // Juniper
        db.insert("00:05:85", "Juniper Networks");
        db.insert("00:12:1E", "Juniper Networks");
        db.insert("00:19:E2", "Juniper Networks");
        db.insert("00:21:59", "Juniper Networks");

        // Palo Alto Networks
        db.insert("00:1B:17", "Palo Alto Networks");
        db.insert("00:30:48", "Palo Alto Networks");

        // Fortinet
        db.insert("00:09:0F", "Fortinet Inc.");
        db.insert("00:1F:FE", "Fortinet Inc.");

        // Aruba Networks
        db.insert("00:0B:86", "Aruba Networks");
        db.insert("00:1A:1E", "Aruba Networks");
        db.insert("00:24:6C", "Aruba Networks");

        // Ubiquiti
        db.insert("00:15:6D", "Ubiquiti Networks");
        db.insert("00:27:22", "Ubiquiti Networks");
        db.insert("04:18:D6", "Ubiquiti Networks");

        // Raspberry Pi
        db.insert("B8:27:EB", "Raspberry Pi Foundation");
        db.insert("DC:A6:32", "Raspberry Pi Foundation");

        // IoT Devices
        db.insert("00:17:88", "Philips Lighting");
        db.insert("EC:FA:BC", "Nest Labs");
        db.insert("18:B4:30", "Nest Labs");
        db.insert("64:16:66", "Amazon Technologies");
        db.insert("CC:9E:A2", "Amazon Technologies");

        db
    };
}

/// MAC address vendor lookup service
pub struct MacVendorLookup;

impl MacVendorLookup {
    /// Lookup vendor from MAC address
    pub fn lookup(mac_address: &str) -> Option<String> {
        let normalized = Self::normalize_mac(mac_address)?;
        let oui = &normalized[..8]; // First 3 bytes (XX:XX:XX format)

        OUI_DATABASE.get(oui).map(|v| v.to_string())
    }

    /// Normalize MAC address to XX:XX:XX format
    fn normalize_mac(mac: &str) -> Option<String> {
        // Remove common delimiters
        let cleaned: String = mac.chars().filter(|c| c.is_ascii_hexdigit()).collect();

        if cleaned.len() != 12 {
            return None;
        }

        // Format as XX:XX:XX:XX:XX:XX
        Some(format!(
            "{}:{}:{}",
            &cleaned[0..2].to_uppercase(),
            &cleaned[2..4].to_uppercase(),
            &cleaned[4..6].to_uppercase()
        ))
    }

    /// Identify device category from vendor
    pub fn identify_category(vendor: &str) -> DeviceCategory {
        let vendor_lower = vendor.to_lowercase();

        if vendor_lower.contains("cisco")
            || vendor_lower.contains("juniper")
            || vendor_lower.contains("aruba")
            || vendor_lower.contains("ubiquiti")
        {
            DeviceCategory::NetworkEquipment
        } else if vendor_lower.contains("vmware")
            || vendor_lower.contains("microsoft")
            || vendor_lower.contains("linux")
        {
            DeviceCategory::VirtualMachine
        } else if vendor_lower.contains("apple")
            || vendor_lower.contains("dell")
            || vendor_lower.contains("hp")
            || vendor_lower.contains("lenovo")
        {
            DeviceCategory::Workstation
        } else if vendor_lower.contains("raspberry") || vendor_lower.contains("arduino") {
            DeviceCategory::EmbeddedDevice
        } else if vendor_lower.contains("nest")
            || vendor_lower.contains("philips")
            || vendor_lower.contains("amazon")
        {
            DeviceCategory::IoTDevice
        } else if vendor_lower.contains("fortinet") || vendor_lower.contains("palo alto") {
            DeviceCategory::SecurityAppliance
        } else {
            DeviceCategory::Unknown
        }
    }

    /// Extended lookup from online API (placeholder for future implementation)
    pub async fn lookup_online(_mac_address: &str) -> Result<String, String> {
        // Placeholder for API integration with macvendors.com or similar
        Err("Online lookup not implemented".to_string())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceCategory {
    NetworkEquipment,
    VirtualMachine,
    Workstation,
    EmbeddedDevice,
    IoTDevice,
    SecurityAppliance,
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cisco_lookup() {
        let vendor = MacVendorLookup::lookup("00:00:0C:12:34:56");
        assert_eq!(vendor, Some("Cisco Systems".to_string()));
    }

    #[test]
    fn test_vmware_lookup() {
        let vendor = MacVendorLookup::lookup("00:50:56:AB:CD:EF");
        assert_eq!(vendor, Some("VMware".to_string()));
    }

    #[test]
    fn test_apple_lookup() {
        let vendor = MacVendorLookup::lookup("00:25:00:11:22:33");
        assert_eq!(vendor, Some("Apple Inc.".to_string()));
    }

    #[test]
    fn test_normalize_mac_colons() {
        let normalized = MacVendorLookup::normalize_mac("00:50:56:ab:cd:ef");
        assert_eq!(normalized, Some("00:50:56".to_string()));
    }

    #[test]
    fn test_normalize_mac_hyphens() {
        let normalized = MacVendorLookup::normalize_mac("00-50-56-ab-cd-ef");
        assert_eq!(normalized, Some("00:50:56".to_string()));
    }

    #[test]
    fn test_normalize_mac_no_delimiter() {
        let normalized = MacVendorLookup::normalize_mac("005056abcdef");
        assert_eq!(normalized, Some("00:50:56".to_string()));
    }

    #[test]
    fn test_invalid_mac() {
        let vendor = MacVendorLookup::lookup("invalid");
        assert_eq!(vendor, None);
    }

    #[test]
    fn test_identify_category_cisco() {
        let category = MacVendorLookup::identify_category("Cisco Systems");
        assert_eq!(category, DeviceCategory::NetworkEquipment);
    }

    #[test]
    fn test_identify_category_vmware() {
        let category = MacVendorLookup::identify_category("VMware");
        assert_eq!(category, DeviceCategory::VirtualMachine);
    }

    #[test]
    fn test_identify_category_iot() {
        let category = MacVendorLookup::identify_category("Nest Labs");
        assert_eq!(category, DeviceCategory::IoTDevice);
    }

    #[test]
    fn test_identify_category_security() {
        let category = MacVendorLookup::identify_category("Palo Alto Networks");
        assert_eq!(category, DeviceCategory::SecurityAppliance);
    }
}
