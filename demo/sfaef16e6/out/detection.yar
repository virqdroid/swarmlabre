// Agent Swarms run sfaef16e6. TLP:AMBER. Prepared by swarmlabre on 2026-11-13.
// Every rule was matched against the source sample by swarmlabre's own matcher (not by YARA) before it was written here.

rule Swarmlabre_ELF_4f514261553c {
    meta:
        description = "Byte-checked strings from the Linux ELF sample, SHA-256 4f514261553c3026... (4 strings, at least 3 must be present)"
        author = "swarmlabre"
        date = "2026-11-13"
        reference = "Agent Swarms run sfaef16e6"
        hash = "4f514261553c3026e9c926b58395d14446e8fbab6799dbc6dc4dd3749bcaf564"
        tlp = "AMBER"
        sample_type = "Linux ELF"
        source = "strings swarmlabre byte-checked in the sample"
        false_positives = "see the note in the report; not tested on clean files"
    strings:
        $s1 = "https://updates.example.test/check" ascii
        $s2 = "Global\\Demo2Lock" ascii
        $s3 = "/tmp/.demo-cache" ascii
        $w1 = "C:\\Demo\\agent.dll" wide
    condition:
        uint32(0) == 0x464c457f and filesize < 1MB and 3 of them
}
