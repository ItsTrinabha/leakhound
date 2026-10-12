import math

import pytest

from fakes import ALNUM, HEX, rand
from leakhound.entropy import EntropySettings, iter_candidates, shannon_entropy


@pytest.mark.parametrize(
    ("value", "expected"),
    [("", 0.0), ("aaaa", 0.0), ("ab", 1.0), ("abcd", 2.0), ("0123456789abcdef", 4.0)],
)
def test_shannon_entropy_known_values(value, expected):
    assert math.isclose(shannon_entropy(value), expected)


def candidates(text, **kwargs):
    return list(iter_candidates(text, EntropySettings(**kwargs)))


def test_random_base64_value_in_assignment_is_detected():
    token = rand(ALNUM, 40)
    found = candidates(f'signing_salt = "{token}"\n')
    assert [c.token for c in found] == [token]
    assert found[0].kind == "base64"


def test_short_random_token_detected_thanks_to_length_aware_threshold():
    token = rand(ALNUM, 24)
    assert [c.token for c in candidates(f"value: {token}")] == [token]


def test_random_hex_value_is_detected_as_hex():
    token = rand(HEX, 64)
    found = candidates(f"webhook_key = '{token}'")
    assert [(c.token, c.kind) for c in found] == [(token, "hex")]


@pytest.mark.parametrize(
    "line",
    [
        'class_name = "UserAccountSettingsRepositoryFactory"',  # identifier, no digits
        'commit = "9fceb02d0ae598e95dc970b74767f19372d61af8"',  # hex on a hash line
        'request_id = "550e8400-e29b-41d4-a716-446655440000"',  # UUID
        'img = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ"',
        "path = 'src/components/forms/UserProfileCard'",
        "callSomeFunction(aRandomLookingArgument12345)",  # not in a value position
        'short = "aB3dE5gH"',  # too short
    ],
)
def test_near_misses_are_ignored(line):
    assert candidates(line) == []


def test_disabled_detector_yields_nothing():
    assert candidates(f'x = "{rand(ALNUM, 40)}"', enabled=False) == []


def test_thresholds_are_configurable():
    token = rand(ALNUM, 40)
    assert candidates(f'x = "{token}"', base64_threshold=5.9) == []
