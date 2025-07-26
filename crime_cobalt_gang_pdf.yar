rule Cobaltgang_PDF_Metadata_Rev_A
{
    meta:
        description = "Find documents saved from the same potential Cobalt Gang PDF template"
        author = "Palo Alto Networks Unit 42"
        category = "PDF"
        date = "2025-07-25"

    strings:
      $ = "<xmpMM:DocumentID>uuid:31ac3688-619c-4fd4-8e3f-e59d0354a338" ascii wide

    condition:
      any of them
}
