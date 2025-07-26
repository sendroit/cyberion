
rule Office_Macro_Threat
{
    meta:
        description = "Detects potentially malicious Office macros"
        author = "Cyberion Security"
        category = "Office"
        
    strings:
        $macro1 = "Auto_Open" nocase
        $macro2 = "Document_Open" nocase
        $macro3 = "Workbook_Open" nocase
        $shell1 = "Shell" nocase
        $shell2 = "cmd.exe" nocase
        $download = "URLDownloadToFile" nocase
        
    condition:
        any of ($macro*) and any of ($shell*, $download)
}

rule Office_Embedded_Object
{
    meta:
        description = "Detects Office documents with embedded objects"
        author = "Cyberion Security"
        category = "Office"
        
    strings:
        $obj1 = "oleObject" nocase
        $obj2 = "package" nocase
        $obj3 = "Equation.3" nocase
        
    condition:
        any of them
}