from controller.mtd_manager import MTDManager


def test_mtd_rotation_changes_target():
    m = MTDManager(["10.0.0.10", "10.0.0.11"], interval=1, seed=7)
    first = m.state.active_target
    second = m.force_rotate().active_target
    assert second != first
    assert m.state.generation == 1
