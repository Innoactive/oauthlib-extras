# coding=utf-8
import os

from setuptools import setup, find_packages


def readme():
    """
    try to read the readme.md file and emit it's content as
    python-friendly ReStructuredText
    :return:
    """
    readme_name = 'readme.md'
    if os.path.isfile(readme_name):
        try:
            from pypandoc import convert
            return convert(readme_name, 'rst')
        except ImportError:
            print("warning: pypandoc module not found, could not execute Markdown to RST")
            with open(readme_name) as f:
                return f.read()

setup(
    name='oauthlib_extras',
    version='1.0',
    description='Extends the oauthlib package with additional grant types',
    long_description=readme(),
    url='https://github.com/Innoactive/oauthlib-extras',
    author='Amar Cutura',
    author_email='amar.cutura@innoactive.de',
    license='MIT',
    platforms='any',
    keywords=['oauth', 'oauthlib', 'grant'],
    packages=find_packages(exclude=['docs', 'tests', 'tests.*']),
    install_requires=[
        'requests_oauthlib'
    ],
    test_suite='nose.collector',
    tests_require=['nose'],
    include_package_data=True
    )
