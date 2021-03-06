# Install

We provide three installation types. You can clone from github,
install by pip, or use yum.

## Git clone
With clone you can import the code in your environment:

    git clone https://github.com/falon/wildfire-milter.git

You could have a virtual env with **python3**, and there you must
install these requirements:

    pip3 install pan-python patool pymilter python-magic \
    PyYAML redis setuptools utils

Python3 is a requirement. Don't try to install under python2.

Rename the `WildfireMilter/etc/milter.conf.dist` in `milter.conf`.
    
## Install with pip

At the moment the package is only under the test pypi. So you can

    pip3 install --index-url https://test.pypi.org/simple wildfire-milter

## Red Hat Installation

If you like there is an easy installation under Red Hat.
Red Hat or Centos >=7 is required. The deployment requires systemd.

If you are in a Red Hat 8 system, then

    curl -1sLf \
      'https://dl.cloudsmith.io/public/csi/wildmilter/cfg/setup/bash.rpm.sh' \
      | sudo bash
    
If you are in a Red Hat 7 system, then

    curl -1sLf \
      'https://dl.cloudsmith.io/public/csi/wildmilter/cfg/setup/bash.rpm.sh' \
      | sudo distro=el codename=8 bash

Finally:

    yum install wildfire-milter

With this installation all must work as is. The setup provides configuration,
 tmpdir, system user and group, services and timers.

You still have to change the configuration file in order to write
your API KEY for WildFire and the Redis access.

    systemctl enable wildfire-milter
    systemctl enable wfverdictchange.timer

From version 0.1-post33 Wildfire Milter integrates with Systemd notify. Because `python3-systemd`
is not easy to find on EL7, you could need an EL8 based OS to install the higher releases of this
milter.

If someone is interested to install wildfire-milter in Red Hat EL7 using yum could write me directly,
I can provide a python-systemd rpm file for EL7 and python3.6.
 All other dependencies working for EL8 are suitable for EL7 too.

# Configuration
You must at least configure in *milter.conf* the `Redis:` section and the `Wildfire:` section.
If you didn't install from **yum**, you have to create the `TMPDIR`.

The log dir could be necessary too, or you can configure log
over syslog.

See at the other config options in *milter.conf* to arrange the configuration as you like.

Maybe you should install some helper archive programs. So patool can work as expected
with all archive formats. See at patool documentation.

# Open Issue
WildFire Milter eats a lot of memory. In a production environment with about 600 mails/300s
we can arrive at 3.5GB of RSS.
In systemd we limit the memory to 3GB. Above this limit the system starts to swap.
You can change this parameter in `wildfire-milter.service` systemd file:

	[Service]
	...
	MemoryLimit=3G

From version 0.1-post37 the Milter dies if the memory usage is higher than `MAX_RSS` config parameter.
In this case systemd can restart the milter _on_failure_.
