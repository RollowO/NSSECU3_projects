rule None_Batch_Logic_Specific {
    meta:
        description = "Detects simple logic/puzzle batch files in the None category"
        false_positives = "Excludes standard Windows system scripts (System32)"
    strings:
        // Header with mandatory newline to ensure it's the start of a command
        $echo_off = { 40 65 63 68 6f 20 6f 66 66 ( 0d 0a | 0a ) }

        // Logic Markers found in the None cluster
        $arithmetic = "set /a " nocase
        $random = "%random%" nocase
        $loop_l = "for /l " nocase
        $loop_f = "for /f " nocase
        $delayed = "setlocal enabledelayedexpansion" nocase
        // Matches simple variable assignments like 'set input=hello' or 'set word=test'
        $simple_assign = /set [a-z0-9_]+=[a-z0-9. !?|]+/ nocase

        // System Script Markers (To exclude False Positives like msdtcvtr.bat)
        $sys_arg = "%~"         // Argument expansion (e.g., %~1, %~dp0) - Very common in system files
        $sys_label = "goto :"     // Internal script labels - Rare in these simple toy scripts
        $sys_params = "%*"        // Capturing all parameters
        $sys_shift = "shift"      // Command used in system scripts to process args
        $sys_exist = "if exist " nocase // File system checks
        $sys_msdtc = "msdtc" nocase    // Specific to the false positive reported
    condition:
        // Global Exclusions (No EXEs, No Python)
        uint16(0) != 0x5a4d and uint8(0) != 0x23 and

        // Logic check
        $echo_off at 0 and
        (any of ($arithmetic, $random, $loop_l, $loop_f, $delayed, $simple_assign)) and
        
        // Exclusion check: Must NOT contain system script patterns
        not (any of ($sys_arg, $sys_label, $sys_params, $sys_shift, $sys_exist, $sys_msdtc))
}