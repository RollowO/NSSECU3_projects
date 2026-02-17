rule Windows_Script_Component_UTF8_Standard {
    meta:
        description = "Detects standard Windows Script Components encoded in UTF-8"
        file_type = "Windows_Script_Component_UTF_8_1"
    strings:
        // Matches BOM + <# + Newline + .SYNOPSIS
        $pattern = { ef bb bf 3c 23 [1-2] 2e 53 59 4e 4f 50 53 49 53 }
    condition:
        $pattern at 0
}

rule Windows_Script_Component_Fuzzy {
    meta:
        description = "Detects files similar to Windows Script Components even with byte variations"
        note = "Allows for 1-2 byte changes in the header or missing BOM"
    strings:
        // 1. Flexible Magic: Allows variations in the BOM or the start tag
        $magic_1 = { ef bb bf 3c 23 } 
        $magic_2 = { 3c 23 } // Just the comment tag
        
        // 2. Structural Keywords
        $s1 = ".SYNOPSIS" ascii wide
        $s2 = ".DESCRIPTION" ascii wide
        $s3 = ".EXAMPLE" ascii wide
        
        // 3. Common content
        $c1 = "Installs" ascii
        $c2 = "Prints" ascii
    condition:
        // Must start with a script tag at the very beginning (offset 0-3)
        ($magic_1 at 0 or $magic_2 in (0..3)) and 
        // Must contain at least 2 structural or content markers
        (2 of ($s1, $s2, $s3, $c1, $c2))
}