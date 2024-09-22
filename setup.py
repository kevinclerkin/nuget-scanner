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
    author='Kevin Clerkin',
    description='A tool to scan NuGet packages for vulnerabilities',  
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    url='https://github.com/kevinclerkin/nuget-scanner',
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.6',
)
