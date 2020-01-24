from setuptools import setup

with open("README.md", "r") as fh:
    long_description = fh.read()

setup(
    name='wildfire-milter',
    version='0.1.post25',
    description='A milter which interfaces to Wildfire Palo Alto API',
    long_description=long_description,
    long_description_content_type="text/markdown",
    keywords="milter Postfix security antivirus mail Wildfire PaloAlto",
    packages=['WildfireMilter'],
    scripts=['wildfire-milter.py', 'wfverdictchange.py'],
    include_package_data = False,
    package_data={
        '': ['etc/milter.conf.dist'],
    },
    data_files=[
        ('/etc/wildfire-milter', ['WildfireMilter/etc/milter.conf.dist']),
        ('/usr/share/doc/wildfire-milter', ['README.md', 'INSTALL.md']),
        ('/usr/share/licenses/wildfire-milter', ['LICENSE']),
        ('/usr/lib/systemd/system', ['WildfireMilter/systemd/wfverdictchange.service',
                                     'WildfireMilter/systemd/wildfire-milter.service',
                                     'WildfireMilter/systemd/wfverdictchange.timer']),
        ('/usr/lib/tmpfiles.d', ['WildfireMilter/systemd/wildfire-milter.conf']),
        ('/etc/logrotate.d', ['WildfireMilter/systemd/wildfire-milter.logrotate'])
    ],
    install_requires=[
        'pan-python>=0.15.0',
        'patool>=1.12',
        'pymilter>=1.0.4',
        'python-magic>=0.4.15, <1.0',
        'PyYAML>=5.2',
        'redis>=3.3',
    ],
    python_requires='>=3.6',
    url='https://github.com/falon/wildfire-milter',
    license='Apache License 2.0',
    author='Marco Favero',
    author_email='m.faverof@gmail.com',
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 4 - Beta",
        "Environment :: No Input/Output (Daemon)",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3.6",
        "Topic :: Communications :: Email",
        "Topic :: Communications :: Email :: Filters"
    ]
)
