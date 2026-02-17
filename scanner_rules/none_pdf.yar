rule NoneFiles_PDF_clusterA_v1
{
    meta:
        description = "PDF header plus dataset-specific binary comment sequence"
        author = "DFIR_yara_bot"
        created = "2026-02-16"
        cluster = "PDF-like None files"

    strings:
        $pdf_header = "%PDF-" ascii
        $pdf_comment_a = { 25 F6 E4 FC DF 0A }
        $pdf_comment_b = { 25 E2 E3 CF D3 0A }

    condition:
        $pdf_header at 0 and
        any of ($pdf_comment_a, $pdf_comment_b) and
        filesize < 10MB
}

rule Specific_PDF_5 {
    meta:
        description = "Detects exactly 5 specific PDF header variations based on user provided hex"
        author = "Gemini"
        date = "2026-02-17"
        type = "brute_force_header"

    strings:
        // File 123: PDF 1.5, CRLF, %b5 signature
        $file_123 = { 25 50 44 46 2d 31 2e 35 0d 0a 25 b5 b5 b5 b5 0d 0a 31 20 30 20 6f 62 6a 0d 0a 3c 3c 2f 54 79 70 65 2f 43 61 74 61 6c 6f 67 2f 50 61 67 65 73 20 32 20 }

        // File 132: PDF 1.6, CR, %e2 signature, Obj 431
        $file_132 = { 25 50 44 46 2d 31 2e 36 0d 25 e2 e3 cf d3 0d 0a 34 33 31 20 30 20 6f 62 6a 0d 3c 3c 2f 4c 69 6e 65 61 72 69 7a 65 64 20 31 2f 4c 20 35 38 38 31 35 32 }

        // File 135: PDF 1.7, CR, %e2 signature, Obj 1
        $file_135 = { 25 50 44 46 2d 31 2e 37 0d 25 e2 e3 cf d3 0d 0a 31 20 30 20 6f 62 6a 0a 3c 3c 2f 41 63 72 6f 46 6f 72 6d 20 35 20 30 20 52 2f 4c 61 6e 67 28 65 6e 29 }

        // File 182: PDF 1.4, CR, %e2 signature, Obj 1213
        $file_182 = { 25 50 44 46 2d 31 2e 34 0d 25 e2 e3 cf d3 0d 0a 31 32 31 33 20 30 20 6f 62 6a 0d 3c 3c 2f 4c 69 6e 65 61 72 69 7a 65 64 20 31 2f 4c 20 34 39 30 38 36 }

        // File 199: PDF 1.7, CRLF, %b5 signature
        $file_199 = { 25 50 44 46 2d 31 2e 37 0d 0a 25 b5 b5 b5 b5 0d 0a 31 20 30 20 6f 62 6a 0d 0a 3c 3c 2f 54 79 70 65 2f 43 61 74 61 6c 6f 67 2f 50 61 67 65 73 20 32 20 }

    condition:
        // Match if ANY of these 5 specific strings appear at the very start of the file
        (
            $file_123 at 0 or 
            $file_132 at 0 or 
            $file_135 at 0 or 
            $file_182 at 0 or 
            $file_199 at 0
        )
}