rule UTF16_LE_License_Headers {
    meta:
        description = "Detects UTF-16LE encoded License files (MIT, Eclipse, CC, Edu) without BOM"
        author = "Gemini"
        date = "2026-02-17"
        type = "text_header_analysis"

    strings:
        // 'wide' in YARA automatically handles the "Char + 0x00" pattern found in your hex.
        
        // Matches "MIT License"
        $lic_mit = "MIT License" wide
        
        // Matches "Eclipse Public License"
        $lic_eclipse = "Eclipse Public License" wide
        
        // Matches "Attribution 4.0" (Common in Creative Commons)
        $lic_cc = "Attribution 4.0" wide
        
        // Matches "Educational Community"
        $lic_edu = "Educational Community" wide

    condition:
        // The file must START (at offset 0) with one of these license names.
        // This effectively filters out random files that just *contain* the words later on.
        (
            $lic_mit at 0 or 
            $lic_eclipse at 0 or 
            $lic_cc at 0 or 
            $lic_edu at 0
        )
}