import pytest

from detect_secrets.plugins.api_key import ApiKeyDetector


class TestApiKeyDetector:

    @pytest.mark.parametrize(
        'payload, should_flag',
        [
            ('0acc94f4-4388-4061-b845-9b3434b2e3f5', True),
        ],
    )
    def test_analyze_line(self, payload, should_flag):
        logic = ApiKeyDetector()

        output = logic.analyze_line(filename='mock_filename', line=payload)
        assert len(output) == int(should_flag)
