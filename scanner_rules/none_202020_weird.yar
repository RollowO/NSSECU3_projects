rule ASCII_Indented_Headers {
    meta:
        description = "Detects ASCII text files with whitespace-padded headers (WTFPL, EUPL, Install Docs)"
        author = "Gemini"
        date = "2026-02-17"
        type = "text_header_analysis"

    strings:
        // File 091: Matches the WTFPL License title
        $wtfpl = "DO WHAT THE FUCK YOU WANT TO PUBLIC" ascii

        // File 217: Matches the EUPL License title
        // Note: Captures 'LICENC' to match the hex provided (ending in 43)
        $eupl = "EUROPEAN UNION PUBLIC LICENC" ascii

        // File 099: Matches the specific installation step
        // Includes the quote character (") which is hex 22
        $install_step = "\"1. Install and configure" ascii

    condition:
        // We do not use 'at 0' because of the variable whitespace (20 20...)
        // Instead, we check if these headers appear within the first 50 bytes.
        (
            $wtfpl in (0..50) or 
            $eupl in (0..50) or 
            $install_step in (0..50)
        )
}