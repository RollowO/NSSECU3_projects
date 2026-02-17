rule Suspect_Group_File046 {
    meta:
        description = "Matches File046 (MZ)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 00 01 01 00 00 00 08 00 10 00 ff ff 08 00 00 01 00 00 00 00 00 00 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 80947 and filename matches /File\d{3}/
}

rule Suspect_Group_File067 {
    meta:
        description = "Matches File067 (MZ variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 93 00 03 00 00 00 20 00 00 00 ff ff 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 366608 and filename matches /File\d{3}/
}
rule Suspect_Group_File155 {
    meta:
        description = "Matches File155 (MZ variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 50 00 02 00 00 00 04 00 0f 00 ff ff 00 00 b8 00 00 00 00 00 00 00 40 00 1a 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 301568 and filename matches /File\d{3}/
}
rule Suspect_Group_File159 {
    meta:
        description = "Matches File159 (MZ variant)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 8b 00 03 00 00 00 20 00 00 00 ff ff 07 00 00 01 65 40 00 00 00 00 40 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 }
    condition:
        $header at 0 and filesize == 317088 and filename matches /File\d{3}/
}
rule Suspect_Group_File200 {
    meta:
        description = "Matches File200 (PNG)"
        author = "Forensics Deduplication Script"
    strings:
        $header = { 4d 5a 00 00 00 0d 49 48 44 52 00 00 03 88 00 00 04 ec 08 06 00 00 00 c2 72 ac 0c 00 01 00 00 49 44 41 54 78 9c ec fd 59 b3 64 49 92 1e 88 7d aa 6a 76 }
    condition:
        $header at 0 and filesize == 1543898 and filename matches /File\d{3}/
}
