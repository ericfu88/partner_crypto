import os
from setuptools import setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='xealth-partner-crypto',
    version='0.1',
    include_package_data=True,
    license='TBD License',  # example license
    url='https://github.com/ericfu88/partner_crypto',
    author='Eric Fu',
    author_email='ericfu88@gmail.com',
    packages=['xealth'],
    install_requires=open('requirements.txt').read().splitlines(),
    classifiers=[
    ],
)
