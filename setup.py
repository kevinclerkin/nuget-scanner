from setuptools import setup, find_packages

setup(
    name='nuget-scanner',
    version='0.1.0',
    packages=find_packages(),
    install_requires=[
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'nuget-scanner = nuget_scanner:main',
        ],
    },
)