use anyhow::{anyhow, Result};
use std::net::IpAddr;

/// Packet fragmentation configuration
#[derive(Debug, Clone)]
pub struct FragmentationConfig {
    /// Enable fragmentation (-f flag)
    pub enabled: bool,
    /// Maximum Transmission Unit (--mtu flag)
    pub mtu: Option<usize>,
    /// Fragment size in bytes (default: 8 bytes for -f)
    pub fragment_size: usize,
    /// Offset fragmentation to evade IDS
    pub offset_evade: bool,
}

impl Default for FragmentationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mtu: None,
            fragment_size: 8,
            offset_evade: false,
        }
    }
}

impl FragmentationConfig {
    /// Create new fragmentation config
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable basic fragmentation (-f flag: 8-byte fragments)
    pub fn enabled() -> Self {
        Self {
            enabled: true,
            mtu: None,
            fragment_size: 8,
            offset_evade: false,
        }
    }

    /// Create with custom MTU (--mtu flag)
    pub fn with_mtu(mtu: usize) -> Result<Self> {
        if mtu < 20 {
            return Err(anyhow!("MTU must be at least 20 bytes (IP header size)"));
        }
        if mtu > 65535 {
            return Err(anyhow!("MTU cannot exceed 65535 bytes"));
        }

        // Calculate fragment size from MTU
        // MTU includes IP header (20 bytes), so data = MTU - 20
        let fragment_size = mtu.saturating_sub(20);

        Ok(Self {
            enabled: true,
            mtu: Some(mtu),
            fragment_size,
            offset_evade: false,
        })
    }

    /// Enable offset evasion (randomize fragment offsets)
    pub fn with_offset_evade(mut self) -> Self {
        self.offset_evade = true;
        self
    }

    /// Get fragment size for data payload
    pub fn data_fragment_size(&self) -> usize {
        self.fragment_size
    }

    /// Check if fragmentation is needed for payload
    pub fn should_fragment(&self, payload_size: usize) -> bool {
        self.enabled && payload_size > self.fragment_size
    }
}

/// IP fragment metadata
#[derive(Debug, Clone)]
pub struct IpFragment {
    /// Fragment data
    pub data: Vec<u8>,
    /// Fragment offset (in 8-byte units)
    pub offset: u16,
    /// More fragments flag
    pub more_fragments: bool,
    /// Fragment identification
    pub id: u16,
}

impl IpFragment {
    pub fn new(data: Vec<u8>, offset: u16, more_fragments: bool, id: u16) -> Self {
        Self {
            data,
            offset,
            more_fragments,
            id,
        }
    }

    /// Get offset in bytes
    pub fn offset_bytes(&self) -> usize {
        (self.offset as usize) * 8
    }

    /// Check if this is the last fragment
    pub fn is_last(&self) -> bool {
        !self.more_fragments
    }
}

/// Packet fragmenter for splitting packets to evade firewalls
pub struct PacketFragmenter {
    config: FragmentationConfig,
    next_id: u16,
}

impl PacketFragmenter {
    /// Create new fragmenter with configuration
    pub fn new(config: FragmentationConfig) -> Self {
        Self {
            config,
            next_id: rand::random(),
        }
    }

    /// Create fragmenter with default -f behavior (8-byte fragments)
    pub fn with_default_fragmentation() -> Self {
        Self::new(FragmentationConfig::enabled())
    }

    /// Create fragmenter with custom MTU
    pub fn with_mtu(mtu: usize) -> Result<Self> {
        Ok(Self::new(FragmentationConfig::with_mtu(mtu)?))
    }

    /// Fragment a payload into multiple IP fragments
    pub fn fragment(&mut self, payload: &[u8]) -> Result<Vec<IpFragment>> {
        if !self.config.enabled {
            return Err(anyhow!("Fragmentation not enabled"));
        }

        if payload.is_empty() {
            return Err(anyhow!("Cannot fragment empty payload"));
        }

        let fragment_size = self.config.data_fragment_size();
        let fragment_id = self.next_fragment_id();
        let mut fragments = Vec::new();

        // Split payload into chunks
        let chunks: Vec<&[u8]> = payload.chunks(fragment_size).collect();
        let total_chunks = chunks.len();

        for (i, chunk) in chunks.iter().enumerate() {
            let is_last = i == total_chunks - 1;
            let offset = if self.config.offset_evade {
                // Add random offset variation for IDS evasion
                self.calculate_evade_offset(i, fragment_size)
            } else {
                // Standard sequential offset (in 8-byte units)
                ((i * fragment_size) / 8) as u16
            };

            let fragment = IpFragment::new(
                chunk.to_vec(),
                offset,
                !is_last,
                fragment_id,
            );

            fragments.push(fragment);
        }

        Ok(fragments)
    }

    /// Fragment a TCP SYN packet for stealth scanning
    pub fn fragment_syn_packet(
        &mut self,
        target: IpAddr,
        port: u16,
    ) -> Result<Vec<IpFragment>> {
        // Create minimal TCP SYN packet payload
        let tcp_header = self.create_tcp_syn_header(target, port);
        self.fragment(&tcp_header)
    }

    /// Get next fragment ID (increments for each packet)
    fn next_fragment_id(&mut self) -> u16 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        id
    }

    /// Calculate offset with evasion (randomized but valid)
    fn calculate_evade_offset(&self, index: usize, fragment_size: usize) -> u16 {
        // Standard offset in bytes
        let standard_offset = index * fragment_size;
        
        // Convert to 8-byte units (IP fragment offset unit)
        (standard_offset / 8) as u16
        
        // Note: True randomization would require reordering fragments,
        // which could break reassembly. For now, use sequential offsets.
        // Advanced evasion can be added later with proper tracking.
    }

    /// Create minimal TCP SYN header (20 bytes)
    fn create_tcp_syn_header(&self, _target: IpAddr, port: u16) -> Vec<u8> {
        let mut header = vec![0u8; 20];
        
        // Source port (random)
        let src_port = rand::random::<u16>();
        header[0..2].copy_from_slice(&src_port.to_be_bytes());
        
        // Destination port
        header[2..4].copy_from_slice(&port.to_be_bytes());
        
        // Sequence number (random)
        let seq = rand::random::<u32>();
        header[4..8].copy_from_slice(&seq.to_be_bytes());
        
        // Acknowledgment number (0 for SYN)
        header[8..12].copy_from_slice(&[0, 0, 0, 0]);
        
        // Data offset (5 = 20 bytes) + flags (SYN = 0x02)
        header[12] = 0x50; // 5 << 4 (data offset)
        header[13] = 0x02; // SYN flag
        
        // Window size (1024)
        header[14..16].copy_from_slice(&1024u16.to_be_bytes());
        
        // Checksum (0 for now, would be calculated by kernel)
        header[16..18].copy_from_slice(&[0, 0]);
        
        // Urgent pointer (0)
        header[18..20].copy_from_slice(&[0, 0]);
        
        header
    }

    /// Get configuration
    pub fn config(&self) -> &FragmentationConfig {
        &self.config
    }

    /// Check if fragmentation is enabled
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Fragment reassembler for reconstructing fragmented packets
pub struct FragmentReassembler {
    /// Fragments by ID
    fragments: std::collections::HashMap<u16, Vec<IpFragment>>,
    #[allow(dead_code)]
    timeout: u64,
}

impl FragmentReassembler {
    /// Create new reassembler with timeout
    pub fn new(timeout: u64) -> Self {
        Self {
            fragments: std::collections::HashMap::new(),
            timeout,
        }
    }

    /// Add fragment to reassembler
    pub fn add_fragment(&mut self, fragment: IpFragment) -> Option<Vec<u8>> {
        let id = fragment.id;
        
        // Add to fragment list
        self.fragments.entry(id).or_insert_with(Vec::new).push(fragment);
        
        // Try to reassemble if we have all fragments
        if self.is_complete(id) {
            self.reassemble(id)
        } else {
            None
        }
    }

    /// Check if all fragments for an ID are received
    fn is_complete(&self, id: u16) -> bool {
        if let Some(frags) = self.fragments.get(&id) {
            // Check if we have a fragment with more_fragments = false (last fragment)
            if !frags.iter().any(|f| !f.more_fragments) {
                return false;
            }
            
            // Check if we have all fragments in sequence
            let mut sorted = frags.clone();
            sorted.sort_by_key(|f| f.offset);
            
            let mut expected_offset = 0u16;
            for frag in &sorted {
                if frag.offset != expected_offset {
                    return false; // Missing fragment
                }
                // Calculate next expected offset
                expected_offset += (frag.data.len() / 8) as u16;
            }
            
            true
        } else {
            false
        }
    }

    /// Reassemble fragments into complete payload
    fn reassemble(&mut self, id: u16) -> Option<Vec<u8>> {
        let fragments = self.fragments.remove(&id)?;
        
        // Sort by offset
        let mut sorted = fragments;
        sorted.sort_by_key(|f| f.offset);
        
        // Validate offsets are sequential
        let mut expected_offset = 0u16;
        for frag in &sorted {
            if frag.offset != expected_offset {
                // Missing fragment or out of order
                return None;
            }
            expected_offset += (frag.data.len() / 8) as u16;
        }
        
        // Concatenate data
        let mut data = Vec::new();
        for frag in sorted {
            data.extend_from_slice(&frag.data);
        }
        
        Some(data)
    }

    /// Clear old fragments (for timeout handling)
    pub fn clear(&mut self) {
        self.fragments.clear();
    }

    /// Get number of incomplete fragment sets
    pub fn incomplete_count(&self) -> usize {
        self.fragments.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fragmentation_config_default() {
        let config = FragmentationConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.fragment_size, 8);
        assert!(config.mtu.is_none());
    }

    #[test]
    fn test_fragmentation_config_enabled() {
        let config = FragmentationConfig::enabled();
        assert!(config.enabled);
        assert_eq!(config.fragment_size, 8);
    }

    #[test]
    fn test_fragmentation_config_with_mtu() {
        let config = FragmentationConfig::with_mtu(1500).unwrap();
        assert!(config.enabled);
        assert_eq!(config.mtu, Some(1500));
        assert_eq!(config.fragment_size, 1480); // 1500 - 20 (IP header)
    }

    #[test]
    fn test_fragmentation_config_mtu_too_small() {
        let result = FragmentationConfig::with_mtu(10);
        assert!(result.is_err());
    }

    #[test]
    fn test_fragmentation_config_mtu_too_large() {
        let result = FragmentationConfig::with_mtu(70000);
        assert!(result.is_err());
    }

    #[test]
    fn test_should_fragment() {
        let config = FragmentationConfig::enabled();
        assert!(config.should_fragment(16));
        assert!(!config.should_fragment(8));
        assert!(!config.should_fragment(4));
    }

    #[test]
    fn test_fragment_basic() {
        let mut fragmenter = PacketFragmenter::with_default_fragmentation();
        let payload = vec![0u8; 24]; // 24 bytes -> 3 fragments of 8 bytes
        
        let fragments = fragmenter.fragment(&payload).unwrap();
        assert_eq!(fragments.len(), 3);
        
        // Check first fragment
        assert_eq!(fragments[0].data.len(), 8);
        assert_eq!(fragments[0].offset, 0);
        assert!(fragments[0].more_fragments);
        
        // Check last fragment
        assert_eq!(fragments[2].data.len(), 8);
        assert_eq!(fragments[2].offset, 2); // 16 bytes / 8 = 2
        assert!(!fragments[2].more_fragments);
    }

    #[test]
    fn test_fragment_with_mtu() {
        let mut fragmenter = PacketFragmenter::with_mtu(100).unwrap();
        let payload = vec![0u8; 200];
        
        let fragments = fragmenter.fragment(&payload).unwrap();
        assert!(fragments.len() >= 2);
        
        // Each fragment should be <= 80 bytes (100 - 20 for IP header)
        for frag in &fragments[..fragments.len() - 1] {
            assert!(frag.data.len() <= 80);
        }
    }

    #[test]
    fn test_fragment_empty_payload() {
        let mut fragmenter = PacketFragmenter::with_default_fragmentation();
        let result = fragmenter.fragment(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fragment_not_enabled() {
        let config = FragmentationConfig::default(); // not enabled
        let mut fragmenter = PacketFragmenter::new(config);
        let result = fragmenter.fragment(&[1, 2, 3]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fragment_id_increments() {
        let mut fragmenter = PacketFragmenter::with_default_fragmentation();
        let payload = vec![0u8; 16];
        
        let frags1 = fragmenter.fragment(&payload).unwrap();
        let frags2 = fragmenter.fragment(&payload).unwrap();
        
        assert_ne!(frags1[0].id, frags2[0].id);
    }

    #[test]
    fn test_reassembler_basic() {
        let mut reassembler = FragmentReassembler::new(30);
        
        // Create 3 fragments
        let frag1 = IpFragment::new(vec![1, 2, 3, 4, 5, 6, 7, 8], 0, true, 100);
        let frag2 = IpFragment::new(vec![9, 10, 11, 12, 13, 14, 15, 16], 1, true, 100);
        let frag3 = IpFragment::new(vec![17, 18, 19, 20, 21, 22, 23, 24], 2, false, 100);
        
        assert!(reassembler.add_fragment(frag1).is_none());
        assert!(reassembler.add_fragment(frag2).is_none());
        
        let result = reassembler.add_fragment(frag3);
        assert!(result.is_some());
        
        let data = result.unwrap();
        assert_eq!(data.len(), 24);
        assert_eq!(data[0], 1);
        assert_eq!(data[23], 24);
    }

    #[test]
    fn test_reassembler_out_of_order() {
        let mut reassembler = FragmentReassembler::new(30);
        
        let frag1 = IpFragment::new(vec![1, 2, 3, 4, 5, 6, 7, 8], 0, true, 200);
        let frag3 = IpFragment::new(vec![17, 18, 19, 20, 21, 22, 23, 24], 2, false, 200);
        let frag2 = IpFragment::new(vec![9, 10, 11, 12, 13, 14, 15, 16], 1, true, 200);
        
        // Add out of order
        reassembler.add_fragment(frag3);
        reassembler.add_fragment(frag1);
        let result = reassembler.add_fragment(frag2);
        
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.len(), 24);
    }

    #[test]
    fn test_reassembler_multiple_ids() {
        let mut reassembler = FragmentReassembler::new(30);
        
        // Two different packets
        let frag1_id100 = IpFragment::new(vec![1, 2, 3, 4, 5, 6, 7, 8], 0, false, 100);
        let frag1_id200 = IpFragment::new(vec![10, 20, 30, 40, 50, 60, 70, 80], 0, false, 200);
        
        let result1 = reassembler.add_fragment(frag1_id100);
        let result2 = reassembler.add_fragment(frag1_id200);
        
        assert!(result1.is_some());
        assert!(result2.is_some());
        assert_ne!(result1.unwrap(), result2.unwrap());
    }

    #[test]
    fn test_ip_fragment_offset_bytes() {
        let frag = IpFragment::new(vec![1, 2, 3], 5, true, 1);
        assert_eq!(frag.offset_bytes(), 40); // 5 * 8 = 40
    }

    #[test]
    fn test_ip_fragment_is_last() {
        let frag1 = IpFragment::new(vec![1], 0, true, 1);
        let frag2 = IpFragment::new(vec![2], 1, false, 1);
        
        assert!(!frag1.is_last());
        assert!(frag2.is_last());
    }
}
