rule APT_Training_Marker
{
    meta:
        description = "Demonstration rule for a synthetic APT training marker"
        author = "ElevanceSkills Internship Training"
        purpose = "YARA syntax and workflow demonstration only"
        warning = "Not a malware detection rule"

    strings:
        $marker = "APT_TRAINING_MARKER_001" ascii

    condition:
        $marker
}