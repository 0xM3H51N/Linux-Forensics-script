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
procs = ['ps', 'aux']
services = ['ls','/etc/init.d']
Logs = ['ls','/var/log/']
net_conn = ['netstat','-natp']
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
bashrc = homedir + '/.bashrc'
history = homedir + '/.bash_history'
vim_info = homedir + '/.viminfo'


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
	if readtype == 'readlines':
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
		f = open(fileToWrite,'x')
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
collect(history, 'History:','readlines')
collect(crontab, 'Cron jobs:\n', 'readlines')
collect(interfaces, 'Network config:\n', 'readlines')
collect(dns_config, 'DNS information:\n','readlines')
collect(vim_info, 'Files accessed using vim:\n','readlines')
ctc(ip,'ip.txt','Network info\n')
ctc(net_conn,'network_conn.txt', 'Active network connections:\n')
ctc(login, 'login.txt', 'Login info:\n')
ctc(procs, 'proc.txt', 'Running processes:\n')
ctc(Logs, 'logs.txt', 'Logs:\n',)
