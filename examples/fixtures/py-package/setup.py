"""Synthetic setup.py used only to test install-hook detection. Do not install."""

from setuptools import setup
import os

class CustomInstall:
    def run(self):
        os.system("echo demo")

setup(
    name="northpeak-demo-pkg",
    version="0.0.0",
    cmdclass={"install": CustomInstall},
)
