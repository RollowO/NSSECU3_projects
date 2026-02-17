rule Windows_Resource_Fragment_Structure {
    meta:
        description = "Detects binary files matching a specific Windows Resource/Dialog structure (Ordinal Marker + Style Flag)"
        author = "Gemini"
        date = "2026-02-17"
        type = "binary_structure_analysis"

    strings:
        /* HEX BREAKDOWN & WILDCARDS:
           Header (10 bytes):
           ?? ?? ?? ??    = Variable ID/Version
           00 00          = consistently 00 in samples
           ?? ??          = Variable Size/Count
           00 00          = consistently 00 in samples
           
           Marker (2 bytes):
           ff ff          = The Resource Ordinal Marker (Offset 10)
           
           Variable ID (4 bytes):
           ?? ?? ?? ??    = Varies (e.g., 00 00 b8 00 vs 05 00 00 01)
           
           Padding (6 bytes):
           00 00 00 00 00 00 = consistently 00 in samples
           
           Style Flag (4 bytes):
           40 00 00 00    = Common Window Style Flag (Offset 22)
        */
        
        $resource_struct = { 
            // 0-9: Header with wildcards for variable parts
            ?? ?? ?? ?? 00 00 ?? ?? 00 00 
            
            // 10-11: The Ordinal Marker
            ff ff 
            
            // 12-15: Variable Resource ID
            ?? ?? ?? ?? 
            
            // 16-21: Zero Padding
            00 00 00 00 00 00 
            
            // 22-25: The Style Flag
            40 00 00 00 
        }

    condition:
        // The structure must align exactly at the start of the file
        $resource_struct at 0
}