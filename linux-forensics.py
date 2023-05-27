import os
import subprocess
import argparse


parser = argparse.ArgumentParser(description='Forensic tool')
parser.add_argument('output_file', type=str, help='Output file name')
args = parser.parse_args()

text_file = open(args.output_file + '.txt', 'w')
html_file = open(args.output_file + '.html', 'w')

homedir = os.getenv('HOME')
ip = ['ip', 'a']
login = ['last', '-F']
procs = ['ps', 'auxf']
proc_tree = ['pstree']
services = ['service', '--status-all']
Logs = ['ls', '/var/log/']
net_conn = ['netstat', '-natpl']
hostname = '/etc/hostname'
timezone = '/etc/timezone'
os_release = '/etc/os-release'
passwd = '/etc/passwd'
group = '/etc/group'
sudoers = '/etc/sudoers'
auth = '/var/log/auth.log'
interfaces = '/etc/network/interfaces'
dns_config = '/etc/hosts'
crontab = '/etc/crontab'
system_crons = ['ls', '-lah', '/etc/cron.d/']
users_cron1 = ['ls', '-lah', '/var/spool/cron/crontabs/']
users_cron2 = ['ls', '-lah', '/var/spool/cron/']
bashrc = homedir + '/.bashrc'
bash_profile = homedir + '/.bash_profile'
history = homedir + '/.bash_history'
vim_info = homedir + '/.viminfo'
ssh_config = '/etc/ssh/sshd_config'
tmp_dir = ['ls', '-lah', '/tmp']
mount = ['mount']
findmnt = ['findmnt']
mounted_disk = ['df', '-aTh']
iptables = ['iptables']

def write_html_header():
    html_file.write("<html>\n")
    html_file.write("<head>\n")
    html_file.write("<title>Forensic Report</title>\n")
    html_file.write("</head>\n")
    html_file.write("<body>\n")
    html_file.write("<h1>Forensic Report</h1>\n")
    html_file.write("<hr>\n")


def write_html_footer():
    html_file.write("</body>\n")
    html_file.write("</html>\n")


def write_html_section(header, content):
    html_file.write("<h2>{}</h2>\n".format(header))
    html_file.write("<pre>{}</pre>\n".format(content))
    html_file.write("<hr>\n")


def collect(filename, header, readtype):
    if readtype == 'read':
        try:
            f = open(filename, 'r').read()
            text_file.write(header + '\n')
            text_file.write(f + '\n')
            write_html_section(header, f)
        except:
            pass
    elif readtype == 'readlines':
        try:
            f = open(filename, 'r').readlines()
            content = ''.join(f)
            text_file.write(header + '\n')
            text_file.write(content + '\n')
            write_html_section(header, content)
        except:
            pass


def ctc(command, fileToWrite, header):
    try:
        sp = subprocess.check_output(command)
        content = sp.decode('utf-8')
        text_file.write(header + '\n')
        text_file.write(content + '\n')
        write_html_section(header, content)
    except:
        pass


write_html_header()

collect(hostname, 'Hostname:', 'read')
collect(os_release, 'OS-release:', 'readlines')
collect(timezone, 'Timezone:', 'read')
collect(passwd, 'User accounts:', 'readlines')
collect(group, 'Group information:', 'readlines')
collect(sudoers, 'Sudoers list:', 'readlines')
collect(auth, 'Authentication log:', 'readlines')
collect(bashrc, 'Bashrc:', 'readlines')
collect(bash_profile, 'bash_profile:', 'readlines')
collect(history, 'History:', 'readlines')
collect(crontab, 'Cron jobs:', 'readlines')
ctc(system_crons, 'system_crons.txt', 'System cron jobs files | /etc/cron.d/ |')
ctc(users_cron1, 'users_cron1.txt', 'Users Crons 1 | /var/spool/cron/crontabs/ |')
ctc(users_cron2, 'users_cron2.txt', 'Users Crons 2 | /var/spool/cron/ |')
collect(interfaces, 'Network config:', 'readlines')
collect(dns_config, 'DNS information:', 'readlines')
collect(vim_info, 'Files accessed using vim:', 'readlines')
collect(ssh_config, 'Users with SSH permissions:', 'readlines')
ctc(ip, 'ip.txt', 'Network info')
ctc(net_conn, 'network_conn.txt', 'Active network connections:')
ctc(login, 'login.txt', 'Login info:')
ctc(procs, 'proc.txt', 'Running processes:')
ctc(Logs, 'logs.txt', 'Logs of the logs/ directory:')
ctc(proc_tree, 'proc_tree.txt', 'Proc_tree:')
ctc(tmp_dir, 'tmp_dir.txt', 'Contents of tmp directory:')
ctc(mount, 'mount.txt', 'Mounted file systems:')
ctc(findmnt, 'findmnt.txt', 'Mounted file systems using findmnt:')
ctc(mounted_disk, 'mounted_disk.txt', 'Listing file system that have been mounted:')
ctc(iptables, 'iptables.txt', 'Listing all iptables rules using "iptables":')
ctc(services, 'service.txt', 'List all services:')

write_html_footer()

text_file.close()
html_file.close()

