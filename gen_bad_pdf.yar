rule SUSP_Bad_PDF
{
    meta:
        description = "Detects PDF that embeds code to steal NTLM hashes"
        author = "Florian Roth (Nextron Systems), Markus Neis"
        category = "PDF"
        date = "2025-07-25"

    strings:
      $s1 = "         /F (http//" ascii
      $s2 = "        /F (\\\\\\\\" ascii
      $s3 = "<</F (\\\\" ascii

    condition:
      ( uint32(0) == 0x46445025 or uint32(0) == 0x4450250a ) and 1 of them
}
