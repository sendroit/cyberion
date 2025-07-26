rule Docm_in_PDF
{
    meta:
        description = "Detects an embedded DOCM in PDF combined with OpenAction"
        author = "Florian Roth (Nextron Systems)"
        date = "2025-07-25"

    strings:
        $s1 = "AutoOpen" ascii fullword
        $s2 = "Macros" wide fullword

    condition:
        (
        uint32be(0) == 0xd0cf11e0 or 	// DOC, PPT, XLS
        uint32be(0) == 0x504b0304		// DOCX, PPTX, XLSX (PKZIP)
        )
        and all of ($s*) and filesize < 300000
        meta:
        description = "Detects an Microsoft Office saved as a MHTML file (false positives are possible but rare; many matches on CVE-2012-0158)"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Florian Roth (Nextron Systems)"
        date = "2015-05-28"
        score = 40
        reference = "https://www.trustwave.com/Resources/SpiderLabs-Blog/Malicious-Macros-Evades-Detection-by-Using-Unusual-File-Format/"
        hash1 = "8391d6992bc037a891d2e91fd474b91bd821fe6cb9cfc62d1ee9a013b18eca80"
        hash2 = "1ff3573fe995f35e70597c75d163bdd9bed86e2238867b328ccca2a5906c4eef"
        hash3 = "d44a76120a505a9655f0224c6660932120ef2b72fee4642bab62ede136499590"
        hash4 = "5b8019d339907ab948a413d2be4bdb3e5fdabb320f5edc726dc60b4c70e74c84"
        id = "21c0c3da-7295-54ad-9947-557a3180af3a"
    strings:
        $s1 = "Content-Transfer-Encoding: base64" ascii fullword
        $s2 = "Content-Type: application/x-mso" ascii fullword
        $x1 = "QWN0aXZlTWltZQA" ascii 	// Base64 encoded 'ActiveMime'
        $x2 = "0M8R4KGxGuE" ascii 		// Base64 encoded office header D0CF11E0A1B11AE1..

    condition:
        uint32be(0) == 0x4d494d45 // "MIME" header
        and all of ($s*) and 1 of ($x*)
        meta:
      description = "Detects an embedded DOCM in PDF combined with OpenAction"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-05-15"
      id = "08dfdfda-8ea5-530d-b89b-560415855080"
    strings:
      $a1 = /<<\/Names\[\([\w]{1,12}.docm\)/ ascii
      $a2 = "OpenAction" ascii fullword
      $a3 = "JavaScript" ascii fullword

    condition:
      uint32(0) == 0x46445025 and all of them
}
