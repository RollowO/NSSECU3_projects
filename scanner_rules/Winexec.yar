rule CSV_Targeted_Masquerade {
    meta:
        description = "Detects exact masqueraded executable patterns from the provided CSV while avoiding system false positives."
        author = "AI Assistant"

    strings:
        // Pattern A: The JPEG-Masqueraded Executable (19 files in CSV)
        // This targets the specific header and the exact quantization table found in your executables
        $jpeg_exec = { ff d? ff e? 00 10 ( 4a 46 49 46 | 45 58 49 46 ) 00 01 01 00 00 01 00 01 00 00 ff db 00 43 00 08 06 06 07 06 05 08 07 07 07 09 09 08 0a 0c 14 0d 0c 0b 0b 0c 19 12 13 0f }

        // Pattern B: The MP3/DOS Polyglot (2 files in CSV)
        // Starts with MP3 sync bits but contains the DOS stub memory structure immediately after
        $mp3_dos_polyglot = { ff fb 90 00 03 00 00 00 04 00 00 00 ff ff 00 00 b8 }

        // Pattern C: The JPEG/PNG Hybrid (1 file in CSV - File143)
        // Starts with a JPEG header but contains a PNG 'IHDR' block at offset 7
        $jpeg_png_hybrid = { ff d8 ff 00 00 00 0d 49 48 44 52 }

    condition:
        // 1. EXCLUDE standard MZ/PE files (Prevents flagging 1.docx, File005, etc.)
        uint16(0) != 0x5a4d and

        // 2. ONLY flag if one of the specific CSV patterns is found at the very start
        (
            $jpeg_exec at 0 or 
            $mp3_dos_polyglot at 0 or 
            $jpeg_png_hybrid at 0
        )
}