rule Specific_License_Headers_12 {
    meta:
        description = "Detects exactly 12 specific license file headers based on raw hex signatures"
        author = "Gemini"
        date = "2026-02-17"
        type = "brute_force_hex"

    strings:
        // File 003: "Copyright (c) [year] [fullname]" (Universal)
        $file_003 = { 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d 20 5b 66 75 6c 6c 6e 61 6d 65 5d }

        // File 021: 20 Spaces + "GNU AFFERO GENERAL PUBLIC LICE"
        $file_021 = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 41 46 46 45 52 4f 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 }

        // File 026: 20 Spaces + "GNU GENERAL PUBLIC LICENSE"
        $file_026 = { 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 4e 53 45 }

        // File 065: "ISC License" + CRLF + CRLF + "Copyright..."
        $file_065 = { 49 53 43 20 4c 69 63 65 6e 73 65 0d 0a 0d 0a 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d 20 5b 66 75 6c 6c 6e 61 6d 65 5d }

        // File 086: "BSD Zero Clause License" + CRLF + CRLF + "Copyright..."
        $file_086 = { 42 53 44 20 5a 65 72 6f 20 43 6c 61 75 73 65 20 4c 69 63 65 6e 73 65 0d 0a 0d 0a 43 6f 70 79 72 69 67 68 74 20 28 63 29 20 5b 79 65 61 72 5d }

        // File 110: "Microsoft Public License (Ms-PL)"
        $file_110 = { 4d 69 63 72 6f 73 6f 66 74 20 50 75 62 6c 69 63 20 4c 69 63 65 6e 73 65 20 28 4d 73 2d 50 4c 29 }

        // File 137: "Boost Software License - Version"
        $file_137 = { 42 6f 6f 73 74 20 53 6f 66 74 77 61 72 65 20 4c 69 63 65 6e 73 65 20 2d 20 56 65 72 73 69 6f 6e }

        // File 157: "Academic Free License ("AFL") v. 3.0"
        $file_157 = { 41 63 61 64 65 6d 69 63 20 46 72 65 65 20 4c 69 63 65 6e 73 65 20 28 22 41 46 4c 22 29 20 76 2e 20 33 2e 30 }

        // File 168: 20 Spaces + "GNU LESSER GENERAL PUBLIC LICEN"
        $file_168 = {20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 20 47 4e 55 20 4c 45 53 53 45 52 20 47 45 4e 45 52 41 4c 20 50 55 42 4c 49 43 20 4c 49 43 45 4e}

        // File 172: "Mozilla Public License Version 2.0" + CRLF + "======"
        $file_172 = { 4d 6f 7a 69 6c 6c 61 20 50 75 62 6c 69 63 20 4c 69 63 65 6e 73 65 20 56 65 72 73 69 6f 6e 20 32 2e 30 0d 0a 3d 3d 3d 3d 3d 3d }

        // File 179: 2 Tabs + 7 Spaces + "The Artistic License"
        $file_179 = { 09 09 20 20 20 20 20 20 20 54 68 65 20 41 72 74 69 73 74 69 63 20 4c 69 63 65 6e 73 65 }

        // File 188: "Open Software License ("OSL") v. 3.0"
        $file_188 = { 4f 70 65 6e 20 53 6f 66 74 77 61 72 65 20 4c 69 63 65 6e 73 65 20 28 22 4f 53 4c 22 29 20 76 2e 20 33 2e 30 }

    condition:
        // Must match one of these specific hex strings at the very start of the file
        (
            $file_003 at 0 or
            $file_021 at 0 or
            $file_026 at 0 or
            $file_065 at 0 or
            $file_086 at 0 or
            $file_110 at 0 or
            $file_137 at 0 or
            $file_157 at 0 or
            $file_168 at 0 or
            $file_172 at 0 or
            $file_179 at 0 or
            $file_188 at 0
        )
}