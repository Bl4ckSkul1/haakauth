from setuptools import setup, find_packages

setup(
    name="haakauth",
    version="1.0.0",
    description="Authentication & Authorization Security Testing Tool",
    long_description=(
        "HaakAuth automates authentication and authorization security testing. "
        "Modules: JWT attacks, IDOR/BOLA detection, auth bypass, session audit, rate limiting."
    ),
    author="Adrian Martinez",
    author_email="me@adrianmartinez.lat",
    url="https://github.com/Bl4ckSkul1/haakauth",
    packages=find_packages(),
    install_requires=[
        "requests>=2.28.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "haakauth=auth_tester.main:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    keywords="security pentest authentication authorization jwt idor bypass",
)
