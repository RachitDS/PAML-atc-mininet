from src.mtd import MTDManager


def test_mtd_rotates_on_attack_entry_and_changes_target():
    mtd = MTDManager(rotation_interval=5)
    event = mtd.on_attack("HTTP_Flood", force=True)
    assert event is not None
    assert event.old_target == "PLC-A"
    assert event.new_target == "PLC-B"
    assert mtd.rotation_count == 1


def test_mtd_rotates_at_interval():
    mtd = MTDManager(rotation_interval=3)
    assert mtd.on_attack("UDP_Flood") is None
    assert mtd.on_attack("UDP_Flood") is None
    event = mtd.on_attack("UDP_Flood")
    assert event is not None
    assert event.trigger == "ROTATION_INTERVAL"
