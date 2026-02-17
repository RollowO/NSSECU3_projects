rule Microsoft_Office_2007_Strict_v2 {
    meta:
        description = "Strict detection for Office 2007+ documents using unique Bit Flags"
        author = "Gemini"
        version = "2.1"
        target_files = "Fixes File211 (inclusion) and File181 (exclusion)"

    strings:
        /* This hex signature is the key differentiator:
           50 4B 03 04 : PKZIP Header
           14 00       : Version 2.0
           06 00       : Bit Flag (Unique to Office docs in this dataset)
           08 00       : Compression Method (Deflated)
           00 00 21 00 : Specific Modification Time/Date stamp
        */
        $office_magic = { 50 4B 03 04 14 00 06 00 08 00 00 00 21 00 }

        /* Common OOXML folder structures to confirm it is an Office file */
        $s1 = "[Content_Types].xml"
        $s2 = "_rels/.rels"
        $s3 = "word/"
        $s4 = "xl/"
        $s5 = "ppt/"

    condition:
        // 1. Requirement: The specific 14-byte Office header must be at the very start
        $office_magic at 0 and
        
        // 2. Requirement: Must contain at least one Office-specific directory string
        (1 of ($s*))
}

rule MS_Office_Relationships_Variant {
    meta:
        description = "Detects Office files where _rels/.rels is the first entry"
    
    strings:
        $pk_header = { 50 4B 03 04 }
        // Length of '_rels/.rels' is 11 bytes (0B 00 in hex)
        $rels_len = { 0B 00 }
        $rels_name = "_rels/.rels"

    condition:
        // Header at start, filename length at offset 26, and the string at offset 30
        $pk_header at 0 and $rels_len at 26 and $rels_name at 30
}