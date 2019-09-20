from setuptools import setup, find_packages

setup(
    name="PyDreamScreen",
    version="0.0.12",
    packages=find_packages(),
    author="Gregory Dosh",
    author_email="pypi@gregorydosh.com",
    description="Python device discovery and manipulation for DreamScreen HD, "
    "4K, and SideKick devices.",
    license="MIT",
    url="https://github.com/GregoryDosh/pydreamscreen",
    long_description=open("README.rst").read(),
    include_package_data=True,
    install_requires=list(r.strip() for r in open("requirements.txt")),
    platforms="any",
    zip_safe=False,
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
)
