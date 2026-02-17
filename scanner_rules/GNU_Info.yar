rule GNU_Info_Reader_Preamble
{
    meta:
        description = "Detects GNU Info files based on File167's specific license preamble"
        author = "AI Assistant"
        reference_file = "File167"

    strings:
        /* "This is free" - allowing 1-2 byte variation in spacing */
        $s1 = { 54 68 69 73 [1-2] 69 73 [1-2] 66 72 65 65 } 
        
        /* "and unencumbered" - using wildcards for flexibility */
        $s2 = { 61 6e 64 ?? 75 6e 65 6e 63 75 6d 62 65 72 65 64 }
        
        /* "software released" */
        $s3 = { 73 6f 66 74 77 61 72 65 [1-2] 72 65 6c 65 61 73 65 64 }

        /* Structural marker: Unit Separator + LF (Common in Info files) */
        $info_ctrl = { 1F 0A }

    condition:
        /* Flexibility: Trigger if 2 out of 3 text patterns are found at the start */
        /* OR if a text pattern is combined with the structural control character */
        (2 of ($s1, $s2, $s3) in (0..100)) or 
        (1 of ($s1, $s2, $s3) in (0..100) and $info_ctrl)
}