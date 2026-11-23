from harness.datasets import flatten


def test_flatten_system_eventdata_userdata():
    rec = {"Event": {
        "System": {"Provider_attributes": {"Name": "Microsoft-Windows-WMI-Activity"}, "EventID": 5858,
                   "Channel": "Microsoft-Windows-WMI-Activity/Operational",
                   "TimeCreated_attributes": {"SystemTime": "2026-01-01T00:00:00Z"}, "EventRecordID": 7},
        "UserData": {"Operation_ClientFailure_attributes": {"xmlns": "x"},
                     "Operation_ClientFailure": {"Operation": "Win32_NTEventlogFile cleareventlog"}},
    }}
    ev = flatten(rec, "f#7")
    assert ev["Provider_Name"] == "Microsoft-Windows-WMI-Activity"   # S43: Tag_Attribute
    assert ev["@timestamp"] == "2026-01-01T00:00:00Z"
    assert ev["Operation"] == "Win32_NTEventlogFile cleareventlog"   # S86: UserData children
    assert "xmlns" not in ev


def test_flatten_eventdata_does_not_override_system():
    rec = {"Event": {"System": {"EventID": 1, "EventRecordID": 1}, "EventData": {"EventID": "spoof", "Image": "a"}}}
    ev = flatten(rec, "f#1")
    assert ev["EventID"] == 1 and ev["Image"] == "a"


def test_flatten_unnamed_data_elements():
    rec = {"Event": {"System": {"EventID": 325, "EventRecordID": 1},
                     "EventData": {"Data": {"#text": ["NTDS", "C:\\x\\ntds.dit"]}}}}
    assert flatten(rec, "f#1")["Data"] == ["NTDS", "C:\\x\\ntds.dit"]   # S87
