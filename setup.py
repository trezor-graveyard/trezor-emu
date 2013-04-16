from setuptools import setup, find_packages
from os.path import dirname, join


here = dirname(__file__)
setup(
    name='bitkey',
    version='1.0.0',
    author='TBD',
    author_email='TBD@TBD.TBD',
    description='Python implementation of bitkey wallet token',
    long_description=open(join(here, 'README.rst')).read(),
    packages=find_packages(),
    test_suite='tests',
    requires=[
        'ecdsa', 'RPi.GPIO', 'spidev', 'pyserial', 'protobuf'
    ],
    entry_points={
        'console_scripts': [
            'bitkey-server = bitkey:run',
            ]
    },
    include_package_data=True,
    package_data={
        'protobuf': ['*.proto'],
        },
    zip_safe=False
)
