import sys
import argparse
import select
import socket
import hashlib
from base64 import b64encode, b64decode
import json
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto import Random
from Crypto.Util.Padding import pad, unpad

# EncryptIM is a server-client instant messaging program
# It uses Encrypt-then-HMAC encryption
# AES-256b encryption and SHA-256b HMAC

# AES-256 encrypt data using key
def encrypt(data , key):
	# Encrypt
	cipher = AES.new(key , AES.MODE_CBC)
	ciphertext_bytes = cipher.encrypt(pad(data.encode("utf-8") , AES.block_size))
	# Get nonce/IV
	nonce = b64encode(cipher.iv).decode('utf-8')
	# Get ciphertext
	ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
	# Put both into a JSON and return
	message_encrypted = json.dumps({'nonce':nonce , 'ciphertext':ciphertext})
	return message_encrypted

# AES-256 decrypt message using key
def decrypt(message_json , key): # data = (nonce , ciphertext , tag)
	try:
		# Get the JSON encrypted message, load each JSON element into a variable
		message_encrypted = json.loads(message_json)
		nonce = b64decode(message_encrypted['nonce'])
		ciphertext = b64decode(message_encrypted['ciphertext'])
		# Decrypt
		cipher = AES.new(key , AES.MODE_CBC , nonce)
		plaintext = unpad(cipher.decrypt(ciphertext) , AES.block_size)
		return plaintext
	except ValueError:
		print ("Error: wrong key / corrupted message!")
		exit()
	except KeyError:
		print ("Error: wrong key / corrupted message!")
		exit()

# Produce the HMAC function for a message & key (used to get and verify digest)
def prod_HMAC(message , key):
	hmac = HMAC.new(key , digestmod=SHA256)
	hmac.update(message.encode("utf-8"))
	return hmac

# Get the HMAC hash hexdigest for a message & key
def HMAC_digest(message , key):
	hmac = prod_HMAC(message , key)
	return hmac.hexdigest()

# Verify whether a message HMAC'd with a key produces a known mac
def HMAC_verify(message , key , mac):
	# Compute hash
	hmac = prod_HMAC(message , key)
	try:
		# Verify if computed hash matches known mac
		hmac.hexverify(mac)
		return True
	except ValueError:
		print ("Error: HMAC failed, wrong message or key!")
		exit()
	return False

# Encrypts and HMACs data, puts into JSON
def encrypt_and_HMAC(data):
	# Encrypt message
	message_encrypted = encrypt(data , key_conf)
	# Produce HMAC digest of message
	mac = HMAC_digest(message_encrypted , key_auth)
	# Serialize message for sending
	message_and_mac = json.dumps({'message':message_encrypted , 'mac':mac})
	return message_and_mac

# Decrypts and HMAC verifies JSON data, then prints it if valid
def decrypt_verify_and_print_data(data):
	data_JSON = json.loads(data)
	message_encrypted = data_JSON['message']
	mac = data_JSON['mac'].encode('utf-8')
	# Check if HMAC of message is correct
	if not HMAC_verify(message_encrypted , key_auth , mac):
		print("Error: HMAC failed, wrong message or key!")
		exit()
	# Decrypt message
	message = decrypt(message_encrypted , key_conf).decode('utf-8')
	# If message is blank, terminate (?)
	#if message == '' or message == '\n':
	#	if args.hostname[0] == 's': # Server-specific terminations
	#		if r in inputs:
	#			inputs.remove(r)
	#		if r in connections:
	#			connections.remove(r)
	#	r.close()
	#	exit(0)

	sys.stdout.write(message)
	sys.stdout.flush()

def run_server():
	hostname = socket.gethostname()
	sock.bind(('' , port))
	# Wait for incoming connections
	sock.listen(1)
	while 1 < 2:

		# blocks till data is available for reading at one of the sources you tell it abaout
		read , write , exceptional = select.select(inputs , outputs , [])

		for r in read:
			if r is sock: # Accept new connection
				conn , addr = sock.accept()
				inputs.append(conn) # Add connection socket to list of inputs to listen for
				connections.append(conn)
			elif r is sys.stdin: # If data from stdin received, send to client(s)
				data = sys.stdin.readline()

				# Encrypt and HMAC stdin
				message_and_mac = encrypt_and_HMAC(data)
				# Send message and HMAC[k](message)
				for c in connections:
					c.send(message_and_mac.encode("utf-8"))
			else: # If data from connection received, print to screen
				data = r.recv(1024)
				if len(data) > 0:
					decrypt_verify_and_print_data(data)
				else: # Blank string means disconnection (?), so remove from conn lists
					if r in inputs:
						inputs.remove(r)
					if r in connections:
						connections.remove(r)
					r.close()
					exit(0)


def run_client():
	sock.connect((args.hostname[0] , port))
	while 1 < 2:
		
		read , write , exceptional = select.select(inputs , outputs , [])

		for r in read:
			if r is sock: # If receiving a message from the server, print it
				data = r.recv(1024)
				if len(data) > 0:
					decrypt_verify_and_print_data(data)
				else: # Blank string means disconnection, so remove from conn lists
					r.close()
					exit(0)
			else: # If receiving a message from stdin, send it to the server
				data = sys.stdin.readline()

				message_and_mac = encrypt_and_HMAC(data)
				# Send message and HMAC(message)
				sock.send(message_and_mac.encode("utf-8"))


parser = argparse.ArgumentParser()
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument('-c', '--c' , dest='hostname' , nargs=1 , help='connect an IM client to [hostname]')
group.add_argument('-s', '--s' , dest='hostname' , action='store_const' , const='s' , help='run an IM server')
parser.add_argument('-p', '--p' , dest='port' , nargs=1 , default=9999 , help='connect on port [p]')
parser.add_argument('--confkey' , dest='key_conf' , nargs=1 , required=True, help='confidentiality key for AES-256-CBC encryption')
parser.add_argument('--authkey' , dest='key_auth' , nargs=1 , required=True , help='authenticity key for SHA-256-based HMAC')
args = parser.parse_args()

port = int(args.port[0])
key_conf = hashlib.sha256(args.key_conf[0].encode()).digest(); # Ensure key is 256b
key_auth = hashlib.sha256(args.key_auth[0].encode()).digest();

# Initialize socket
sock = socket.socket(socket.AF_INET , socket.SOCK_STREAM)
# Allow reuse of local port socket, in case last execution is still occupying it:
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, port)

# Specify inputs for select
inputs = [sock , sys.stdin]
outputs = []
connections = []

# SERVER
if args.hostname[0] == 's':
	try:
		run_server()
	except KeyboardInterrupt:
		exit(0)

# CLIENT
else:
	try:
		run_client()
	except KeyboardInterrupt:
		exit(0)



