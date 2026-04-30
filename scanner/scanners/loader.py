"""Dynamic scanner loader for SecOps Tool."""
import os
import sys
import importlib
import inspect
from typing import List, Dict, Type
from scanner.scanners.base import BaseScanner


def discover_scanners(scanner_dir: str = None) -> Dict[str, List[BaseScanner]]:
    """
    Dynamically discover and load scanner modules from the scanners directory.
    Returns a dict mapping category names to lists of scanner instances.
    """
    if scanner_dir is None:
        scanner_dir = os.path.dirname(os.path.abspath(__file__))

    scanners_by_category = {
        "sast": [],
        "secrets": [],
        "cve": [],
        "dast": [],
    }

    # Map scanner names to categories based on tool type
    category_keywords = {
        "gosec": "sast",
        "semgrep": "sast",
        "secrets": "secrets",
        "gitleaks": "secrets",
        "cve": "cve",
        "osv": "cve",
        "nuclei": "dast",
        "nuclei_scanner": "dast",
        "NucleiScanner": "dast",
    }

    # Scan for Python files in the scanners directory
    for filename in os.listdir(scanner_dir):
        if not filename.endswith(".py") or filename in ("__init__.py", "base.py"):
            continue

        module_name = filename[:-3]
        try:
            # Import the module dynamically
            module_path = f"scanner.scanners.{module_name}"
            module = importlib.import_module(module_path)

            # Find all BaseScanner subclasses in the module
            for name, obj in inspect.getmembers(module, inspect.isclass):
                if issubclass(obj, BaseScanner) and obj is not BaseScanner:
                    try:
                        instance = obj()
                        # Determine category
                        for keyword, category in category_keywords.items():
                            if keyword in module_name or keyword in name.lower():
                                scanners_by_category[category].append(instance)
                                break
                    except Exception as e:
                        import traceback
                        traceback.print_exc(file=sys.stderr)
                        print(f"Warning: Failed to instantiate {name}: {e}", file=sys.stderr)

        except Exception as e:
            print(f"Warning: Failed to load scanner module {module_name}: {e}", file=sys.stderr)

    return scanners_by_category
