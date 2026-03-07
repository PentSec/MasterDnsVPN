from setuptools import setup
from Cython.Build import cythonize

setup(
    ext_modules=cythonize(
        [
            "dns_utils/DnsPacketParser.py",
            "dns_utils/ARQ.py",
            "dns_utils/DNSBalancer.py",
            "dns_utils/PingManager.py",
        ],
        compiler_directives={"language_level": "3"},
    )
)
