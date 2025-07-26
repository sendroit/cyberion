rule Office_Macro_Suspicious
{
    meta:
        description = "Detect suspicious Office macros"
        author = "Cyberion Security"
        date = "2025-01-01"
        severity = "high"
        category = "office"
        
    strings:
        $m1 = "Auto_Open" nocase
        $m2 = "Document_Open" nocase
        $m3 = "Workbook_Open" nocase
        $m4 = "Shell" nocase
        $m5 = "CreateObject" nocase
        $m6 = "WScript.Shell" nocase
        $m7 = "powershell" nocase
        $m8 = "cmd.exe" nocase
        
    condition:
        (1 of ($m1, $m2, $m3)) and (2 of ($m4, $m5, $m6, $m7, $m8))
}

rule PDF_Javascript_Exploit
{
    meta:
        description = "Detect potentially malicious PDF with JavaScript"
        author = "Cyberion Security"
        date = "2025-01-01"
        severity = "medium"
        category = "pdf"
        
    strings:
        $pdf = "%PDF"
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $js3 = "eval(" nocase
        $js4 = "unescape(" nocase
        
    condition:
        $pdf at 0 and (1 of ($js*))
}
