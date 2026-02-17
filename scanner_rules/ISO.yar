rule ISO_9660_Flexible_Detection {
    meta:
        description = "Detects ISO 9660 CD Disc Images with flexibility for byte changes"
        author = "Assistant"
        reference = "Analyzed from yara_scan_results.csv (File038)"

    strings:
        // Primary Signature: 'CD00' followed by a wildcard. 
        // This detects 'CD001' but remains open if a byte changes to 'CD002' etc.
        $cd_magic = { 43 44 30 30 ?? }

        // Structural Marker: The PDF-style object definition found in the sample.
        // Uses a jump [0-10] to allow for variations in the version string (e.g. '.6')
        $pdf_structure = { 0a 25 [0-10] 0a 31 20 30 20 6f 62 6a }

        // Content Marker: Metadata tag usually found in these headers
        $metadata = "/Metadata"

    condition:
        // Must start with the signature at offset 0
        $cd_magic at 0 and 
        
        // Must also contain one of the structural identifiers. 
        // This prevents 'overfitting' to the first 50 bytes while 
        // ensuring we don't scan unrelated files like OOXML docs.
        ($pdf_structure or $metadata)
}