from setuptools import setup, find_packages

setup(
    name="pivot",
    version="1.0.0",
    description="Secure IP-layer relay for multi-hop vulnerability scanning",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "PyYAML>=6.0",
        "cryptography>=41.0.0",
    ],
    entry_points={
        "console_scripts": [
            "pivot-agent=pivot.agent.main:main",
            "pivot-client=pivot.client.main:main",
        ],
    },
)
