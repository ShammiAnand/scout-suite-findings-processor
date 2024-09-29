import pytest
from typing import Dict, List, Any, Tuple
from collections import deque


def parse_json_path(data: Dict[str, Any], path: str) -> List[Tuple[str, Any]]:
    def traverse(
        current_data: Any, path_parts: deque, current_path: List[str]
    ) -> List[Tuple[str, Any]]:
        if not path_parts:
            return [((".".join(current_path), current_data))]
        current_part = path_parts.popleft()
        results = []
        if current_part == "id":
            if isinstance(current_data, dict):
                for key, value in current_data.items():
                    new_path = current_path + [key]
                    results.extend(traverse(value, path_parts.copy(), new_path))
            else:
                return []
        elif isinstance(current_data, dict) and current_part in current_data:
            new_path = current_path + [current_part]
            results.extend(traverse(current_data[current_part], path_parts, new_path))
        else:
            return []
        return results

    path_parts = deque(path.split("."))
    return traverse(data, path_parts, [])


@pytest.fixture
def sample_data():
    return {
        "awslambda": {
            "regions": {
                "us-east-1": {
                    "functions": {
                        "func1": {"arn": "arn1", "runtime": "python3.8"},
                        "func2": {"arn": "arn2", "runtime": "nodejs14.x"},
                    }
                },
                "us-west-2": {
                    "functions": {"func3": {"arn": "arn3", "runtime": "java11"}}
                },
            }
        }
    }


def test_parse_json_path(sample_data):
    display_path = "awslambda.regions.id.functions.id"
    result = parse_json_path(sample_data, display_path)

    expected_paths = [
        "awslambda.regions.us-east-1.functions.func1",
        "awslambda.regions.us-east-1.functions.func2",
        "awslambda.regions.us-west-2.functions.func3",
    ]
    expected_keys = [{"arn", "runtime"}, {"arn", "runtime"}, {"arn", "runtime"}]

    assert len(result) == len(expected_paths)

    for (path, value), exp_path, exp_keys in zip(result, expected_paths, expected_keys):
        assert path == exp_path
        assert set(value.keys()) == exp_keys


def test_parse_json_path_empty_result(sample_data):
    display_path = "nonexistent.path"
    result = parse_json_path(sample_data, display_path)
    assert result == []


def test_parse_json_path_partial_match(sample_data):
    display_path = "awslambda.regions.us-east-1.functions"
    result = parse_json_path(sample_data, display_path)
    assert len(result) == 1
    assert result[0][0] == "awslambda.regions.us-east-1.functions"
    assert set(result[0][1].keys()) == {"func1", "func2"}


def test_parse_json_path_id_not_dict(sample_data):
    sample_data["non_dict"] = "string"
    display_path = "non_dict.id"
    result = parse_json_path(sample_data, display_path)
    assert result == []
