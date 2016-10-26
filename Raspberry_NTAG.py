#!/usr/bin/env python3
import smbus
import math
import re
import subprocess
import shlex
import os
import time
import signal
import functools
import argparse

# common i2c functions are:
# read_byte(addr)
# write_byte(addr, val)
# read_byte_data(addr, cmd)
# write_byte_data(addr, cmd, val)
# read_word_data(addr, cmd)
# write_word_data(addr, cmd, val)
# read_i2c_block_data(addr, cmd, count)
# write_i2c_block_data(addr, cmd, vals)

class TimedOut(Exception):
	pass

def call_with_timeout(timeout, f, *args, **kwargs):
	"""Call f with the given arguments, but if timeout seconds pass before
	f returns, raise TimedOut. The exception is raised asynchronously,
	so data structures being updated by f may be in an inconsistent state.
	"""
	def handler(signum, frame):
		raise TimedOut("Timed out after {} seconds.".format(timeout))

	old = signal.signal(signal.SIGALRM, handler)
	try:
		signal.alarm(timeout)
		try:
			return f(*args, **kwargs)
		finally:
			signal.alarm(0)
	finally:
		signal.signal(signal.SIGALRM, old)

def with_timeout(timeout):
	"""Decorator for a function that causes it to timeout after the given
	number of seconds.
	"""
	def decorator(f):
		@functools.wraps(f)
		def wrapped(*args, **kwargs):
			return call_with_timeout(timeout, f, *args, **kwargs)
		return wrapped
	return decorator

# def run_program(rcmd):
# Runs a program, and it's parameters (e.g. rcmd = 'ls -lh /var/www')
# Returns output if sucessful, or None and logs error if not.
@with_timeout(50)
def run_program(rcmd, wpacli=False):
	cmd = shlex.split(rcmd)
	try:
		proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		if (wpacli):
			for line in iter(proc.stdout.readline, ''):
				line = line.decode('utf-8')
				if (re.search(r'Trying to associate with', line)) :
					print(line, end='')
					scanned = re.search(r"Trying to associate with\s*(..:..:..:..:..:..).*?SSID='(.*?)'", line)
					if (scanned): print('SSID = "{}", bssid = "{}"'.format(scanned.group(2), scanned.group(1)))
				elif (re.search(r'CTRL-EVENT-CONNECTED - Connection to', line)): # connected
					print(line, end='')
					break
				elif (re.search(r'CTRL-EVENT-REGDOM-CHANGE', line)):
					print(line, end='')
#					break # not connected but could be another ssid to try
				elif (re.search(r'CTRL-EVENT', line) or re.search(r'WPA: 4-Way Handshake failed', line) or
					re.search(r'WPS-AP-AVAILABLE', line) or re.search(r'Associated with', line) or
					re.search(r'WPA: Key negotiation completed with', line)): print(line, end='')
				elif (re.search(r'<\d>', line)): print(line, end='')
			resp = proc.communicate(input=b'quit\n')
		else:
			resp = proc.communicate()
	except TimedOut:
		print('timed out')
		proc.terminate()
		resp = proc.communicate()
	finally:
		return resp

# Function to put credentials to /etc/wpa_supplicant/wpa_supplicant.conf
# Returns True if updated or added, False if nothing to do
def addwpa(ssid, psk):
	if (not ssid or not psk): return
	try:
		f = open('/etc/wpa_supplicant/wpa_supplicant.conf', 'r')
		wpafile = f.read()
		pattern = r'(network\s*=\s*{.*?ssid\s*=\s*"' + ssid + r'".*?psk\s*=\s*")(.*?)(".*?})'
#		print('Search pattern: {}'.format(pattern))
		network = re.search(pattern, wpafile, re.DOTALL)
		if (network): # update exiting network
			oldpsk = network.group(2)
			if (psk != oldpsk): # only do work if needed
				substr = r'\g<1>' + psk + r'\g<3>'
				newfile = re.subn(pattern, substr, wpafile, flags=re.DOTALL) # flags are important
				f = open('/etc/wpa_supplicant/wpa_supplicant.conf', 'w')
				f.write(newfile[0])
				f.close()
				print('Existing Wifi network "{}" has been updated.'.format(ssid))
				return True
			else:
				print('Existing Wifi network "{}" was up to date.'.format(ssid))
				return False
		else: # add new network
			newnet = 'network={\n\tssid="' + ssid + '"\n\tmode=0\n\tpsk="' + psk + '"\n}\n'
			f = open('/etc/wpa_supplicant/wpa_supplicant.conf', 'a')
			f.write(newnet)
			f.close()
			print('New Wifi network "{}" has been added.'.format(ssid))
			return True
	except (OSError, IOError) as err:
		print(err)

def read_ntag():
	bus = smbus.SMBus(1)
	addr = 0x55
	block1 = bus.read_i2c_block_data(addr, 0x01, 16) # read the first user block and check validity
	try:
		if (block1[1] == 0xFF and block[2] != 0xD1):
			raise ValueError('Message has more than 248 characters are not supported')
		if (block1[2] != 0xD1): raise ValueError('It is not a well-known type that I can understand.')
		if (block1[5] != 0x54): raise ValueError('It is not a text NDEF record that I can interpret.')
		recordlen = block1[4]
		payload = block1[9:16]
		i = 0x2
		while i <= 0x2 + math.floor((recordlen-9)/16): # read entire payload record
			block = bus.read_i2c_block_data(addr, i, 16)
			payload = payload + block
			i = i+1
	#	print(' '.join(format(x, '02X') for x in payload))
		del payload[recordlen-2:] # trim the extras
		if (payload[recordlen-3] != 0xFE):
			raise ValueError('Expecting EOF marking 0xFE. Record length incorrect.')
		del payload[recordlen-3:]
		payload = ''.join(chr(x) for x in payload)
		value = re.findall(r'(["\'])(.*?)\1', payload)
		if (len(value)<2): raise ValueError('Please put two values in " " or \' \'.')
		return value[0][1], value[1][1] # return ssid, psk
	except ValueError as err:
		print(err)
	finally:
		bus.close()

	

# main function
def main():
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--force', help='force wifi reconnect', action='store_true')
	args = parser.parse_args()

	username, password = read_ntag()
	if (args.force or addwpa(username, password)):
		# re-start wpa_supplicant
		print('Connecting Wifi ...')
		if (not os.path.isfile('/run/wpa_supplicant.wlan0.pid')):
			print('wpa_supplicant not running')
			resp = run_program('wpa_cli status')
			for x in list(map(lambda x: x.decode('utf-8'), resp)): print(x, end='')
#			run_program('/sbin/wpa_supplicant -s -B -P /run/wpa_supplicant.wlan0.pid -i wlan0 -D nl80211,wext -c /etc/wpa_supplicant/wpa_supplicant.conf')
		else:
			print('ifdown wlan0')
			resp = run_program('ifdown wlan0')
			for x in list(map(lambda x: x.decode('utf-8'), resp)): print(x, end='')
			time.sleep(3)
			print('ifup wlan0')
			resp = run_program('ifup wlan0')
			for x in list(map(lambda x: x.decode('utf-8'), resp)): print(x, end='')
			resp = run_program('wpa_cli', True) # run wpa_cli in interactive mode to get wpa_supplicant output
			for x in list(map(lambda x: x.decode('utf-8'), resp)): print(x, end='')
			resp = run_program('wpa_cli status')
			for x in list(map(lambda x: x.decode('utf-8'), resp)): print(x, end='')
			print('Getting IP address...')
			time.sleep(10)
			ipaddr = subprocess.check_output(['hostname', '-I'])
			print('IP Address: {}'.format(ipaddr))
	else: print('Nothing to do')
	print('Type "sudo startx" to enter graphic mode.')

if __name__ == '__main__':
	main()