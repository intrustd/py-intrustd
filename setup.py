from setuptools import setup, find_packages
from os import path

setup(
    name="intrustd-support",
    version="0.1.0",
    description="Intrustd application support",
    packages=find_packages(),
    install_requires=['requests'],
    test_requires=['pytest']
)
