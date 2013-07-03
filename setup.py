from setuptools import setup, find_packages
from os.path import dirname, join


here = dirname(__file__)
setup(
    name='trezor-emu',
    version='0.1.0',
    author='slush',
    author_email='info@bitcoin.cz',
    description='Python implementation of Trezor hardware wallet',
    long_description=open(join(here, 'README.rst')).read(),
    packages=find_packages(),
    test_suite='tests',
    requires=['ecdsa', 'RPi.GPIO', 'spidev', 'pyserial', 'protobuf', ],
    entry_points={'console_scripts': ['trezor-emu = trezor:run', ], },
    include_package_data=True,
    package_data={'protobuf': ['*.proto'], },
    zip_safe=False
)
