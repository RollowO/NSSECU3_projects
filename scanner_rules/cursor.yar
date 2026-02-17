rule Windows_animated_cursor_detection {
    meta:
        description = "Detects files similar to Windows_animated_cursor samples by matching RIFF/PDF hybrid headers"
        author = "AI Assistant"
        file_type = "Windows_animated_cursor"

    strings:
        /* Pattern: RIFF WAVE-1. followed by 2 variable bytes (version/newline) 
           and the binary PDF header signature 
        */
        $hybrid_magic = { 52 49 46 46 57 41 56 45 2d 31 2e ?? ?? 25 e2 e3 cf d3 }

        /* Common markers found in the analyzed samples */
        $obj_marker = " 0 obj"
        $bracket_marker = "<<"

    condition:
        /* Check for RIFF magic at the start (Little Endian) */
        uint32(0) == 0x46464952 and
        
        /* The hybrid magic must appear at the start, 
           allowing for 1-2 byte changes via wildcards 
        */
        $hybrid_magic at 0 and

        /* Must also contain at least one characteristic keyword */
        ($obj_marker or $bracket_marker)
}