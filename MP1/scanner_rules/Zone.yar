rule ZoneAlam_Structural_Filtered {
    meta:
        description = "Detects disguised ZoneAlam files while excluding app-specific libraries and browser cache files"
        author = "AI Assistant"
        
    condition:
        // 1. MZ Signature (4D 5A)
        uint16(0) == 0x5a4d and
        
        // 2. Specific Page Configuration
        uint16(4) == 0x0003 and
        
        // 3. Header Size
        uint16(8) == 0x0004 and
        
        // 4. Initial SS/SP Values
        uint16(12) == 0xffff and
        
        // 5. Verification of the zero-padding area (Offsets 32 and 36)
        uint32(32) == 0x00000000 and
        uint32(36) == 0x00000000 and
        
        // 6. EXCLUSION A: Ignore all standard compiled extensions
        not (filename matches /\.(exe|dll|sys|pyd|tmp|mui|node|cpl|scr|bin|ocx|ax|winmd|tlb|rll|vdm|odf|db-wal)$/i) and
        
        // 7. EXCLUSION B: Ignore Chromium-based Browser Cache files (e.g., f_000107, f_00001a)
        // These are extensionless cached web executables
        not (filename matches /^f_[0-9a-f]{6}$/i) and
        not (filename matches /^data_[0-9]$/i) and
        filename matches /File\d{3}/
}