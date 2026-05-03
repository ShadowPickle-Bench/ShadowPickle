from setuptools import setup
from setuptools.command.install import install
import site
import sys
import os
import shutil


class CustomInstall(install):
    def run(self):
        install.run(self)

        site_packages = self.install_lib
        pth_file = os.path.join(site_packages, "custom_collections.pth")

        with open(pth_file, "w") as f:
            f.write("import custom_collections_loader\n")

        print(f"Created {pth_file}")


setup(
    name="torch-override",
    version="1.0",
    py_modules=[
        "custom_ordered_dict",
        "custom_collections_loader",
        # "sitecustomize",
    ],
    # data_files=[(site.getsitepackages()[0], ["custom_collections.pth"])],
    cmdclass={
        "install": CustomInstall,
    },
)
