rule Detect_HEIC_File136_Flexible {
    meta:
        description = "Detects HEIC patterns similar to File136 (IHDR start)"
        csv_source = "File136"
        flexibility = "Allows 1-2 byte variations in the header"

    strings:
        // Primary pattern: 4-byte length + "IHDR"
        // We use '??' wildcards to allow 1-2 bytes to change in the header
        $header_varied = { 00 00 00 ?? 49 48 ?? 52 }
        
        // Secondary pattern: "IDAT" marker found at offset 29
        $idat = { 49 44 41 54 }

    condition:
        // Anchor the search to the start of the file (offset 0)
        // This ensures we only catch files like File136 and not standard PNGs
        $header_varied at 0 and 
        
        // Ensure the IDAT marker exists within the first 50 bytes
        $idat in (0..50)
}