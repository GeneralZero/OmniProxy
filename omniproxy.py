#!/usr/bin/env python

from twisted.internet import reactor
from twisted.internet import ssl as twistedssl
import forwarder
from logger_callbacks import SocketLogger

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, dsa, ec
from OpenSSL.crypto import load_certificate, dump_certificate, dump_privatekey, load_privatekey, FILETYPE_PEM
from OpenSSL.SSL import SSLv23_METHOD, Context

import ssl, argparse, os, re, sys

#Creating Custom SSLServerContext
class SNISSLServerContext(twistedssl.DefaultOpenSSLContextFactory):
	def __init__(self, CA,  default_server, default_port, privateKeyFileName, certificateFileName, sslmethod=SSLv23_METHOD):
		self.default_version = sslmethod
		self.default_server = default_server
		self.default_port = default_port
		self.CA = CA

		return super().__init__(privateKeyFileName, certificateFileName, sslmethod)

	def cacheContext(self):
		return super().cacheContext()

	def SNICallback(self, connection):
		prev_context = connection.get_context()

		#Stop Producing Data untill connection is made
		server_object = prev_context._server_context
		server_object.transport.pauseProducing()

		#Get Host from SNI
		host = connection.get_servername()
		if host:
			host = host.decode("utf-8")
		else:
			host = self.default_server

		#Get Certificate from Server
		ssl_certs = self.CA.clone_certificate({"server": host, "port": self.default_port })


		#Update the SSL Context
		new_context = Context(self.default_version)
		new_context.new_host = (host, self.default_port)
		new_context.use_privatekey(load_privatekey(FILETYPE_PEM, open(ssl_certs["keyfile"]).read()))
		new_context.use_certificate(load_certificate(FILETYPE_PEM, open(ssl_certs["certfile"]).read()))
		connection.set_context(new_context)

		#Call Proxy Server to finish setting up the Connection
		server_object.SNICallback(connection)


	def getContext(self):
		self._context.set_tlsext_servername_callback(self.SNICallback)
		#self._context.set_keylog_callback(self.SNICallback)
		return self._context


class CertificateAuthority(object):
	"""docstring for CertificateAuthority"""	
	def __init__(self, ca_file, cache_dir="ssl_cache"):
		#print("Initializing CertificateAuthority ca_file={} cache_dir={}".format(ca_file, cache_dir))
		self.ca_file = ca_file
		self.cache_dir = cache_dir
		self.CERT_PREFIX = "fake_cert"

		if not os.path.exists(cache_dir):
			os.mkdir(cache_dir)

		if not os.path.exists(ca_file):
			raise Exception("No cert exists at {}".format(ca_file))
		else:
			self._read_ca(ca_file)

	def clone_certificate(self, remote_server):
		cert_string = self.get_certificate_from_server(remote_server)

		#Get Certificate properties
		cert_dict = self.parse_pem(cert_string)

		#Check if exists in cache
		cnp = os.path.sep.join([self.cache_dir, '{}-{}.pem'.format(self.CERT_PREFIX, cert_dict["subject"]["commonName"])])
		if os.path.exists(cnp):
			print("Cert already exists common_name={}".format(cert_dict["subject"]["commonName"]))
		else:
			print("Creating and signing cert common_name={}".format(cert_dict["subject"]["commonName"]))

			#Generating the Correct Private Keytype
			if cert_dict["public_key"] == "RSA":
				private_key = rsa.generate_private_key(public_exponent=cert_dict["public_key_pub_exp"],
										key_size=cert_dict["public_key_size"], backend=default_backend())

			elif cert_dict["public_key"] == "DSA":
				private_key = dsa.generate_private_key(key_size=cert_dict["public_key_size"], backend=default_backend())

			elif cert_dict["public_key"] == "EllipticCurve":
				private_key = ec.generate_private_key(cert_dict["public_key_curve"], default_backend())


			#Generate Certificate Signing Request
			csr_subject = cert_dict["subject_object"]

			#csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name(csr_subject))


			#for extension in cert_dict["ext_object"]:
			#	print("{}, {}".format(extension.oid._name, extension.critical))
			#	if extension.oid._name not in ["signedCertificateTimestampList"]:
			#		csr = csr.add_extension(extension.value, critical=extension.critical)

			#csr = csr.sign(private_key, cert_dict["signature_hash_algorithm"], default_backend())

			#Generate Certificate
			cert = x509.CertificateBuilder().subject_name(csr_subject)
			cert = cert.issuer_name(self.cert.subject)
			cert = cert.public_key(private_key.public_key())
			cert = cert.serial_number(cert_dict["serial_number"])
			cert = cert.not_valid_before(cert_dict["not_valid_before"])
			cert = cert.not_valid_after(cert_dict["not_valid_after"])
			for extension in cert_dict["ext_object"]:
				#print("{}, {}".format(extension.oid._name, extension.critical))
				if extension.oid._name not in ["signedCertificateTimestampList"]:
					cert = cert.add_extension(extension.value, critical=extension.critical)
					
			cert = cert.sign(self.key, cert_dict["signature_hash_algorithm"], default_backend())

			# Write our certificate out to disk.
			with open(cnp, 'wb+') as f:
				f.write(cert.public_bytes(serialization.Encoding.PEM))
			with open(cnp[:-3] + "key", 'wb+') as f:
				f.write(private_key.private_bytes(encoding=serialization.Encoding.PEM, encryption_algorithm=serialization.NoEncryption(), format=serialization.PrivateFormat.TraditionalOpenSSL))

		return {"certfile": cnp, "keyfile": cnp[:-3] + "key"}


	def _read_ca(self, file):
		#Load Certificate
		self.cert = load_certificate(FILETYPE_PEM, open(file).read())
		self.cert = x509.load_pem_x509_certificate(dump_certificate(FILETYPE_PEM, self.cert), backend=default_backend())

		#Load Key File
		self.key = load_privatekey(FILETYPE_PEM, open(file).read())
		self.key = serialization.load_pem_private_key(dump_privatekey(FILETYPE_PEM, self.key), password=None, backend=default_backend())

	def parse_pem(self, cert_data):
		try:
			cert = x509.load_pem_x509_certificate(str.encode(cert_data), default_backend())

			cert_dict = {}

			#Clone Serial Number
			cert_dict["serial_number"] = cert.serial_number

			#Keytype
			if isinstance(cert.public_key(), rsa.RSAPublicKey):
				#print("Keytype: RSA")
				cert_dict["public_key"] = "RSA"
				cert_dict["public_key_size"] = cert.public_key().key_size
				cert_dict["public_key_pub_exp"] = cert.public_key().public_numbers().e
			elif isinstance(cert.public_key(), dsa.DSAPublicKey):
				#print("Keytype: DSA")
				cert_dict["public_key"] = "DSA"
				cert_dict["public_key_size"] = cert.public_key().key_size
			elif isinstance(cert.public_key(), ec.EllipticCurvePublicKey):
				#print("Keytype: EllipticCurve")
				cert_dict["public_key"] = "EllipticCurve"
				cert_dict["public_key_size"] = cert.public_key().key_size
				cert_dict["public_key_curve"] = cert.public_key().curve
			else:
				raise Exception("Invalid Keytype")

			#Copy Validity Start Date
			cert_dict["not_valid_before"] = cert.not_valid_before
			
			#Copy Validity End Date
			cert_dict["not_valid_after"] = cert.not_valid_after

			#Use Same Signature Algorithum
			cert_dict["signature_hash_algorithm"] = cert.signature_hash_algorithm

			#Copy Subject and other object data 
			cert_dict["subject"] = dict()
			cert_dict["subject_object"] = cert.subject
			
			for attribute in cert.subject:
				cert_dict["subject"][attribute.oid._name] = attribute.value

			#Do not copy the Origional Issuer Data
			#cert_dict["issuer"] = dict()
			#for attribute in cert.issuer:
				#cert_dict["issuer"][attribute.oid._name] = attribute.value
				#print("Issuer {}: {}".format(attribute.oid._name, attribute.value))

			#Copy the Certificate Extentions
			cert_dict["ext_object"] = cert.extensions
			return cert_dict
		except Exception as e:
			print("Error decoding certificate: {}".format(e))


	def get_certificate_from_server(self, remote_server):
		print("Getting Server Certificate from {}:{}".format(remote_server["server"], remote_server["port"]))
		try:
			with ssl.create_connection((remote_server["server"], remote_server["port"])) as conn:
				context = ssl.SSLContext(ssl.PROTOCOL_TLS)
				sock = context.wrap_socket(conn, server_hostname=remote_server["server"])
				certificate = ssl.DER_cert_to_PEM_cert(sock.getpeercert(True))
				return certificate
		except Exception as e:
			print("Network error: {}".format(e))



if __name__ == '__main__':
	p = argparse.ArgumentParser(description="Modular Intercept Proxy")
	p.add_argument("--local-port","-p",type=int, default=443,
					metavar="<port>",
					help="Local proxy port (default:443)")
	p.add_argument("--destination","-d",default="",
					metavar="<destination>",required=True,
					help="Server Destination example www.google.com:80")
	p.add_argument("--listen-address","-l", default="0.0.0.0",
					metavar="<listen-address>",
					help="Specify the listen address (default is 0.0.0.0)")
	p.add_argument("--tcp", "-t", action='store_true')
	p.add_argument("--udp", "-u", action='store_true')
	p.add_argument("--cafile","-c",	metavar="<certificate-file>") 
	p.add_argument("--log-folder", default="logs")
	p.add_argument("--quiet", "-q", action='store_true')

	args = p.parse_args()

	server = args.destination.split(":")

	# Fix Destination Server and modify defaults
	if len(server) == 2:
		remote_server = {"server": server[0] ,"port": int(server[1])}
	else:
		remote_server = {"server": server[0] ,"port": args.local_port}

	proxy = args.listen_address.split(":")

	# Destination Server
	if len(proxy) == 2:
		proxy_server = {"server": proxy[0] ,"port": int(proxy[1])}
	elif proxy[0].isdigit():
		proxy_server = {server: None, "port": proxy[0]}
		#TODO set default SSL Context 
	else:
		proxy_server = {"server": proxy[0] ,"port": 443}

	#Set Logger Functions
	logger = SocketLogger(args.log_folder, not args.quiet)
	forwarder.setClientReceiveCallback(logger.on_server2client_done_read)
	forwarder.setServerReceiveCallback(logger.on_client2server_done_read)
	forwarder.setClientStartCallback(logger.on_client2server_new_connection)
	forwarder.setServerStartCallback(logger.on_server2client_new_connection)
	forwarder.setClientCloseCallback(logger.on_client2server_close_connection)
	forwarder.setServerCloseCallback(logger.on_server2client_close_connection)


	#Switch on the specific TCP, UDP, SSL Server
	if args.tcp:
		#Start TCP Proxy Server
		forwarder.tcpToTcp(args.listen_address, args.local_port, remote_server["server"], remote_server["port"])

		print("TCP {}:{} -> {}:{}".format(args.listen_address, args.local_port, remote_server["server"], remote_server["port"]))

	elif args.udp:
		#Start USP Proxy Server
		forwarder.udpToUDP(args.listen_address, args.local_port, remote_server["server"], remote_server["port"])

		print("UDP {}:{} -> {}:{}".format(args.listen_address, args.local_port, remote_server["server"], remote_server["port"]))

	else:
		# If using SSL Proxy a CA Certificate is Required
		if not args.cafile:
			raise Exception("CA File Required")

		#Get CA File to sign new Certificates
		CA = CertificateAuthority(args.cafile)
		
		#Get get the default endpoint Certificate
		ssl_certs = CA.clone_certificate(remote_server)

		#Create a Custom SSL Context to clone Certificates and resign them
		serverContextFactory = SNISSLServerContext(CA, remote_server["server"], remote_server["port"], ssl_certs["keyfile"], ssl_certs["certfile"])

		
		forwarder.sslToSSL(args.listen_address, args.local_port, remote_server["server"], remote_server["port"], CA, serverContextFactory)

		print("TCP[SSL] {}:{} -> {}:{}".format(args.listen_address, args.local_port, remote_server["server"], remote_server["port"]))

	reactor.run()
