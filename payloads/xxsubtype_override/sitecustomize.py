import sys
import importlib.util
import os

custom_module_path = os.path.join(os.path.dirname(__file__), "xxsubtype.py")

spec = importlib.util.spec_from_file_location("xxsubtype", custom_module_path)
custom_xxsubtype = importlib.util.module_from_spec(spec)
spec.loader.exec_module(custom_xxsubtype)

sys.modules["xxsubtype"] = custom_xxsubtype
