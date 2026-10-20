"""Package metadata kept compatible with older pip editable installs."""

from pathlib import Path

from setuptools import find_packages, setup


setup(
    name="networksecurity-phishing-triage",
    version="0.2.0",
    description="Offline phishing-feature classification and reproducible evaluation",
    long_description=Path(__file__).with_name("README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Zichen Fan",
    license="MIT",
    python_requires=">=3.9",
    packages=find_packages(),
    install_requires=[],
    extras_require={"mongo": ["pymongo>=4,<5"]},
    entry_points={"console_scripts": [
        "phishing-triage=networksecurity.phishing:main",
        "url-triage=networksecurity.url_triage:main",
    ]},
)
