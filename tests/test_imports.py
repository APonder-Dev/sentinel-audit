from sentinel_audit.collectors.system_info import collect_system_info


def test_collect_system_info_returns_dictionary():
    result = collect_system_info()

    assert isinstance(result, dict)
    assert "hostname" in result
    assert "os" in result