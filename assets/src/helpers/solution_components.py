import logging
import sys
import json
from pathlib import Path

logger = logging.getLogger(__name__)
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def get_files_from_dir(path):
    dashboards_json_elements = {}

    # If folder does not exist, skip gracefully
    if not path.exists() or not path.is_dir():
        logger.warning("Definitions directory missing, skipping: %s", path)
        return dashboards_json_elements

    for child in path.iterdir():
        logger.debug("Object %s found", child)

        # Only include JSON files (skip .DS_Store and others)
        if child.is_file() and child.suffix.lower() == '.json':
            with open(child, encoding='utf-8') as f:
                raw = f.read()
                try:
                    # Strip potential BOM and validate
                    parsed = json.loads(raw.lstrip('\ufeff'))
                    # Only accept JSON objects; skip arrays and other types
                    if not isinstance(parsed, dict):
                        logger.warning("Skipping non-object JSON file (expected object): %s", child)
                        continue
                except Exception:
                    logger.warning("Skipping invalid JSON file: %s", child)
                    continue
                dashboards_json_elements[child.stem] = json.dumps(parsed)
                logger.debug("Object %s read", child)

    return dashboards_json_elements


class SolutionComponents:
    def __init__(self):
        # In the Lambda bundle, JSON assets are placed at ./dashboards_definitions_json
        # rather than ./src/dashboards_definitions_json. Point to the correct location.
        path = Path('./dashboards_definitions_json')

        logger.debug("Entering path %s, attempting to read all Dashboard files", path)

        self.dashboards = get_files_from_dir(path / 'dashboards')
        self.templates = get_files_from_dir(path / 'templates')
        self.index_patterns = get_files_from_dir(path / 'index_patterns')
        self.visualizations = get_files_from_dir(path / 'visualizations')

        logger.info("Components successfully read")
