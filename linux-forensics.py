import os
import subprocess
import argparse


parser = argparse.ArgumentParser(description='Forensic tool')
parser.add_argument('output_file', type=str, help='Output file name')
args = parser.parse_args()

file = open(args.output_file,'x')

homedir = os.getenv('HOME')
ip = ['ip','a']
login = ['last', '-F']
procs = ['ps', 'auxf']
proc_tree = ['pstree']
services = ['service --status-all'] #['ls','/etc/init.d']
Logs = ['ls','/var/log/']
net_conn = ['netstat','-natpl']
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
system_crons = ['ls','-lah','/etc/cron.d/']
users_cron1 =  ['ls','-lah','/var/spool/cron/crontabs/']
users_cron2 = ['ls','-lah','/var/spool/cron/']
bashrc = homedir + '/.bashrc'
bash_profile = homedir + '.bash_profile'
history = homedir + '/.bash_history'
vim_info = homedir + '/.viminfo'
ssh_config = '/etc/ssh/sshd_config'
tmp_dir = ['ls','-lah','/tmp']
mount = ['mount']
findmnt = ['findmnt']
mounted_disk = ['df', '-aTh']
iptables = ['iptables']

def collect(filename, header,readtype):
	if readtype == 'read':
		try:
			f = open(filename,'r').read()
			file.write(header)
			file.write('\t')
			file.write(f)
			file.write('\n-----------------------------------------------\n')
		except:
			pass
	elif readtype == 'readlines':
		try:
			f = open(filename, 'r').readlines()
			file.write(header)
			for line in f:
				file.write('\t')
				file.write(line)
			file.write('\n-----------------------------------------------\n')
		except:
			pass


def ctc(command,fileToWrite,header):
	try:
		sp = subprocess.check_output(command)
		f = open(fileToWrite,'w')
		f.write(sp.decode('utf-8'))
		f.close()
		f = open(fileToWrite,'r').readlines()
		file.write(header)
		for line in f:
			file.write('\t')
			file.write(line)
		os.remove(fileToWrite)
		file.write('\n-----------------------------------------------\n')
	except:
		pass


collect(hostname , 'Hostname:\n', 'read')
collect(os_release,'OS-release:\n','readlines')
collect(timezone, 'Timezone:\n','read')
collect(passwd, 'User accounts:\n', 'readlines')
collect(group, 'Group information:\n', 'readlines')
collect(sudoers,'Sudoers list:\n','readlines')
collect(auth, 'Authentication log:\n', 'readlines')
collect(bashrc, 'Bashrc:\n','readlines')
collect(bash_profile, 'bash_profile:\n','readlines')
collect(history, 'History:','readlines')
collect(crontab, 'Cron jobs:\n', 'readlines')
ctc(system_crons,'system_crons.txt','System cron jobs files | /etc/cron.d/ | \n')
ctc(users_cron1,'users_cron1.txt','Users Crons 1 | /var/spool/cron/crontabs/ | \n')
ctc(users_cron2,'users_cron2.txt','Users Crons 2 | /var/spool/cron/ | \n')
collect(interfaces, 'Network config:\n', 'readlines')
collect(dns_config, 'DNS information:\n','readlines')
collect(vim_info, 'Files accessed using vim:\n','readlines')
collect(ssh_config, 'Users with SSH permissions:\n','readlines')
ctc(ip,'ip.txt','Network info\n')
ctc(net_conn,'network_conn.txt', 'Active network connections:\n')
ctc(login, 'login.txt', 'Login info:\n')
ctc(procs, 'proc.txt', 'Running processes:\n')
ctc(Logs, 'logs.txt', 'Logs of the logs/ directory:\n',)
ctc(proc_tree, 'proc_tree.txt', 'Porc_tree:\n',)
ctc(tmp_dir, 'tmp_dir.txt', 'Contents of tmp directory:\n',)
ctc(mount, 'mount.txt', 'Mounted file systems:\n',)
ctc(findmnt, 'findmnt.txt', 'Mounted file systems using findmnt:\n',)
ctc(mounted_disk, 'mounted_disk.txt', 'Listing file system that have been mounted:\n',)
ctc(iptables, 'iptables.txt', 'Listing all iptables rules using "iptables":\n',)
ctc(services,'service.txt','List all services:\n')

file.close()
