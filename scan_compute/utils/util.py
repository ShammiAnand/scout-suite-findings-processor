from typing import Dict
import ujson
import base64

from datetime import datetime


def resolve_path(
    event: dict,
    path: list,
    resources: list,
    _EMPTY=object(),
):
    """To resolve cloudtrail event resource path.

    Args:
    ----
    event (dict): Cloudtrail event dict.
    path (list): Path of the resource(s).

    Returns:
    -------
        resources (list[list|str]) : A list of list or str of all possible resolved resources, empty if non.

    Raises:
    ------
        Key Error, Attribute Error and Type Error of a path stored in a list and returns it.

    """
    records = {}
    error_list = []
    _chunk = event

    for _id, key in enumerate(path, start=1):
        if key == "id" and type(_chunk) is list:
            _path = path[_id:]
            if _path:
                for _event in _chunk:
                    resolve_path(_event, _path, resources, _EMPTY)
                break
            else:
                resources.extend(_chunk)
        else:
            try:
                _chunk = _chunk[key]  # type: ignore
            except (KeyError, AttributeError, TypeError) as e:
                _chunk = "Error in Path ---> " + str(path) + " , msg ---> " + str(e)
                if _chunk not in error_list:
                    error_list.append(_chunk)
            if not path[_id:] and len(error_list) == 0:
                resources.append(_chunk)
            elif len(error_list) != 0:
                resources = error_list.copy()
            elif _chunk == _EMPTY:
                break
            else:
                continue

    result = list(filter(lambda _: _ != _EMPTY, resources))

    if (len(error_list)) == 0:
        records["error"] = 0
        records["resource_id"] = result
    else:
        records["error"] = 1
        records["error_list"] = result

    return records


def get_diff_from_last_proc(cached_time):
    current_time = datetime.now()
    time_difference = current_time - cached_time
    return max(1, min(time_difference.days, 7))


def base64_to_json(base64_str: str) -> Dict:
    """
    Converts a base64 encoded string back to a JSON object.

    Args:
    base64_str (str): Base64 encoded string of the JSON content.

    Returns:
    dict: JSON object decoded from the base64 string.
    """
    json_str = base64.b64decode(base64_str).decode("utf-8")
    json_data = ujson.loads(json_str)

    return json_data
