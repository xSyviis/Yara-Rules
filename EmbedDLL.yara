rule Yara_EmbedDLL {
    
    meta: 
        last_updated = "2022-08-31"
        author = "Syviis"
        description = "Yara rule for embed.dll Grunt Agent"

    strings:
        // Fill out identifying strings and other criteria      
        $string1 = "EmbedDLL"
        $string2 = "Wscript.Shell"
        $string3 = "embed.xml"
        $string4 = "p0w3r0verwh3lm1ng!"
        $string5 = "CDATA"
        $string6 = "System.IO.Compression.DeflateStream"



    condition:
        // Fill out the conditions that must be met to identify the binary
        $string1 or
        ($string2 and $string3) or
        $string4 or
        ($string5 and $string6)
}