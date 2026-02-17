rule Detect_Specific_CSV_MP3_Variants
{
    meta:
        description = "Targets MP3 files matching specific CSV patterns while ignoring standard system MP3s"
        author = "AI Assistant"
        reference = "Analysis of yara_scan_results.csv"

    strings:
        // Common ID3 Magic - required for both
        $id3_magic = { 49 44 33 }

        // Variant 1 Pattern (Based on File 023)
        // Focuses on the unique version '00 01 01' and the 'ff ff 08' sequence.
        // ?? used to allow for 1-2 byte variations in size/flags.
        $variant_023 = { 49 44 33 00 01 01 ?? ?? ?? 08 ?? 10 ?? ff ff 08 }

        // Variant 2 Pattern (Based on File 063)
        // Focuses on the '1.4' header and the '1 0 obj' PDF-like marker.
        // Standard MP3s like AchievementUnlocked.mp3 will NOT have '1 0 obj'.
        $variant_063_a = { 49 44 33 31 2e 34 0d 25 }
        $variant_063_b = "1 0 obj"

    condition:
        // Only scan files starting with ID3
        $id3_magic at 0 and 
        (
            // Match the specific sparse header from File 023
            $variant_023 at 0 or 
            
            // Match the '1.4' header AND the '1 0 obj' string found in File 063
            ($variant_063_a at 0 and $variant_063_b in (0..100))
        )
}