"""
Setup script for Enterprise Secret Scanner & SCA Tool
"""
from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="enterprise-secret-scanner",
    version="1.0.0",
    author="Enterprise Security Team",
    author_email="security@company.com",
    description="Comprehensive secret detection and vulnerability analysis tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/company/enterprise-secret-scanner",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.2",
            "pytest-cov>=4.1.0",
            "flake8>=6.1.0",
            "black>=23.9.1",
            "isort>=5.12.0",
        ],
        "security": [
            "safety>=2.3.5",
            "pip-audit>=2.6.1",
        ],
    },
    entry_points={
        "console_scripts": [
            "enterprise-scanner=app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["templates/*.html", "static/*.js", "static/*.css", "config/*.yaml"],
    },
)
