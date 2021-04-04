import os
from importlib.machinery import SourceFileLoader

from pkg_resources import parse_requirements
from setuptools import find_packages, setup

module_name = "pochta_squatter"


module = SourceFileLoader(
    module_name, os.path.join(module_name, "__init__.py")
).load_module(module_name)


def load_requirements(file_name: str) -> list:
    requirements = []
    with open(file_name, "r") as fp:
        for req in parse_requirements(fp.read()):
            extras = "[{}]".format("","".join(req.extras)) if req.extras else ""
            requirements.append(
                "{}{}{}".format(req.name, extras, req.specifier)
            )
    return requirements


setup(
    name=module_name,
    author="hjoefung",
    python_requires=">=3.8",
    packages=find_packages(exclude=["tests"]),
    install_requires=load_requirements("requirements.txt"),
    extras_require={"dev": load_requirements("requirements.dev.txt")},
    entry_points={
        "console_scripts": [
            "{0} = {0}:__init__".format(module_name)
        ]
    },
    include_package_data=True
)
