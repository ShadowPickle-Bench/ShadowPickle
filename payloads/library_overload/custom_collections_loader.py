import sys
import importlib.util
import os

custom_module_path = os.path.join(os.path.dirname(__file__), "custom_ordered_dict.py")

# Load our custom module
spec = importlib.util.spec_from_file_location("collections", custom_module_path)
custom_xxsubtype = importlib.util.module_from_spec(spec)
spec.loader.exec_module(custom_xxsubtype)

sys.modules["collections"] = custom_xxsubtype
