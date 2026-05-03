from setuptools import setup, Extension
from setuptools import setup
import site
import sys

if hasattr(sys, "real_prefix") or (
    hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
):
    site_packages = site.getsitepackages()[0]
    print(f"Installing to venv: {site_packages}")
else:
    site_packages = site.getsitepackages()[0]
    print(f"Installing to system: {site_packages}")
setup(
    name="xxsubtype-override",
    version="1.0",
    py_modules=["xxsubtype", "sitecustomize"],
)
