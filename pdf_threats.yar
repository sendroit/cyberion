
rule PDF_JavaScript_Threat
{
    meta:
        description = "Detects PDF with JavaScript"
        author = "Cyberion Security"
        category = "PDF"
        
    strings:
        $pdf_header = "%PDF"
        $js1 = "/JavaScript" nocase
        $js2 = "/JS" nocase
        $action = "/Action" nocase
        
    condition:
        $pdf_header at 0 and any of ($js*, $action)
}

rule PDF_Embedded_File
{
    meta:
        description = "Detects PDF with embedded files"
        author = "Cyberion Security"
        category = "PDF"
        
    strings:
        $pdf_header = "%PDF"
        $embed1 = "/EmbeddedFile" nocase
        $embed2 = "/FileSpec" nocase
        
    condition:
        $pdf_header at 0 and any of ($embed*)
}