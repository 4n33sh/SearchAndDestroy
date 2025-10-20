from setuptools import setup, find_packages

setup(
    name="OceanEyesAPT",
    version="2.0.0",
    author="Team Ocean Eyes",
    description=(
        "OceanEyes – Adaptive APT Detection Framework integrating "
        "ELK, Zeek, Suricata, Sigma, and Machine Learning for dynamic threat hunting."
    ),
    long_description=open("README.md").read() if open("README.md", "r") else "",
    long_description_content_type="text/markdown",
    url="https://github.com/4n33sh/SearchAndDestroy",
    packages=find_packages(),
    include_package_data=True,
    python_requires=">=3.8",
    install_requires=[
        "elasticsearch>=8.14.0",
        "pandas>=2.2.0",
        "numpy>=1.25.0",
        "scikit-learn>=1.3.0",
        "pyyaml>=6.0.2",
        "requests>=2.31.0",
        "tqdm>=4.66.0",
    ],
    entry_points={
        "console_scripts": [
            "oceaneyes=oceaneyes.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Topic :: Security :: Intrusion Detection",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    project_urls={
        "Documentation": "https://github.com/4n33sh/SearchAndDestroy/wiki",
        "Source": "https://github.com/4n33sh/SearchAndDestroy",
        "Tracker": "https://github.com/4n33sh/SearchAndDestroy/issues",
    },
)
