from src.v4_schema import BASE_FEATURES_V4,TEMPORAL_FEATURES_V4,ALL_FEATURES_V4

def test_v4_has_exact_20_features():
    assert len(BASE_FEATURES_V4)==8
    assert len(TEMPORAL_FEATURES_V4)==12
    assert len(ALL_FEATURES_V4)==20
    assert len(set(ALL_FEATURES_V4))==20
