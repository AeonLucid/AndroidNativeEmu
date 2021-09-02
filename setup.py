#!/usr/bin/env python3

from pathlib import Path
from setuptools import setup, find_packages

project_dir = Path(__file__).parent

setup(
    name="androidemu",
    version="0.0.2",
    description="Allows you to partly emulate an Android native library.",
    long_description=project_dir.joinpath("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    keywords=["python"],
    author="AeonLucid",
    author_email="aeonlucid@gmail.com",
    url="https://github.com/AeonLucid/AndroidNativeEmu",
    packages=find_packages("src"),
    package_dir={"": "src"},
    python_requires=">=3.7",
    include_package_data=True,
    install_requires=project_dir.joinpath("requirements.txt").read_text().split("\n"),
    license="GPLv3",
    classifiers=[
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Emulators",
        "Intended Audience :: Developers",
    ],
)
