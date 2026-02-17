rule NoneFiles_PNG_IDAT_variant_v1
{
    meta:
        description = "PNG signature + dataset-specific IDAT/zlib pattern cluster"
        author = "DFIR_yara_bot"
        created = "2026-02-16"
        cluster = "PNG-like None files"

    strings:
        $png_sig = { 89 50 4E 47 0D 0A 1A 0A }
        $idat_zlib_exact = { 49 44 41 54 78 9C EC FD }
        $idat_zlib_wild  = { 49 44 41 54 78 9C ?? ?? }
        $cluster_sig = { C2 72 AC 0C 00 01 00 00 }

    condition:
        $png_sig at 0 and
        ($idat_zlib_exact or $idat_zlib_wild) and
        $cluster_sig in (0..256)
}

rule NoneFiles_PNG_JFIF_variant_v1
{
    meta:
        description = "PNG signature followed by JFIF JPEG header (hybrid variant)"
        author = "DFIR_yara_bot"
        created = "2026-02-17"
        cluster = "PNG-JFIF hybrid None file"

    strings:
        $png_sig = { 89 50 4E 47 0D 0A 1A 0A }
        $jfif    = { 4A 46 49 46 00 }
        $jpeg_qt = { FF DB 00 43 }

    condition:
        $png_sig at 0 and
        $jfif in (8..32) and
        $jpeg_qt in (16..128)
}

