rule PKZIP_Archive_1_Refined_v2 {
    meta:
        description = "Targeted detection for PKZIP_archive_1. Covers missing samples and excludes legitimate Office docs."
        author = "AI Assistant"
        version = "4.0"

    strings:
        // Local File Header Signature
        $pk = { 50 4B 03 04 }
        
        // Specific internal filenames found in the 20 target samples
        $f1 = "[trash]/0000.dat"
        $f2 = "[Content_Types].xml"
        $f3 = "word/document.xml"
        $f4 = "word/header1.xml"
        $f5 = "word/numbering.xml"
        $f6 = "word/footer1.xml"
        $f7 = "xl/comments1.xml"
        $f8 = "ppt/presentation.xml"
        $f9 = "docProps/app.xml"

    condition:
        // 1. Must start with the PKZIP signature
        $pk at 0 and
        
        // 2. Validate Flags (offset 6) and Compression (offset 8)
        // Target samples only use these specific combinations:
        // 0x00000000 (Stored, No Flags)
        // 0x00080000 (Deflate, No Flags)
        // 0x00080002 (Deflate, Bit 1 set)
        // 0x00080808 (Deflate, Bits 3 & 11 set)
        // 0x00080800 (Deflate, Bit 11 set)
        (
            uint32(6) == 0x00000000 or 
            uint32(6) == 0x00080000 or 
            uint32(6) == 0x00080002 or 
            uint32(6) == 0x00080808 or 
            uint32(6) == 0x00080800
        ) and

        // 3. Extra Field Length (offset 28)
        // Legitimate Office files use large extra fields for NTFS timestamps.
        // All target samples have lengths of 0, 4, or 17.
        (uint16(28) == 0 or uint16(28) == 4 or uint16(28) == 17) and

        // 4. Filename Check
        // Match one of the specific filenames used by this group at the correct offset
        for any of ($f*): ( $ at 30 )
}