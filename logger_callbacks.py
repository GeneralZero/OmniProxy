import time, os, string, socket

def hexdump(src, length=16, sep='.'):
	FILTER = ''.join([(len(repr(chr(x))) == 3) and chr(x) or sep for x in range(256)])
	lines = []
	for c in range(0, len(src), length):
		chars = src[c: c + length]
		hex_ = ' '.join(['{:02x}'.format(x) for x in chars])
		if len(hex_) > 24:
			hex_ = '{} {}'.format(hex_[:24], hex_[24:])
		printable = ''.join(['{}'.format((x <= 127 and FILTER[x]) or sep) for x in chars])
		lines.append('{0:08x}  {1:{2}s} |{3:{4}s}|'.format(c, hex_, length * 3, printable, length))
	return '\n'.join(lines)

##Logger Class for the Connection Information
class SocketLogger():
	"""docstring for TCPLogger"""
	def __init__(self, log_folder=False, verbose=True):
		self.connid = 0
		self.verbose = verbose

		self.log_folder = log_folder
		if not os.path.exists(log_folder):
			os.makedirs(log_folder)

	def common_info(self, connection):
		print("Common Info: {}".format(connection))
		connection_dict = {}

		#If SSL
		if connection.__class__.__name__ in ["SSLProxyClient", "SSLProxyServer"]:
			connection_dict['socket_protocol'] = 'ssl'

			#Set ProxyServer Source IP, PORT
			connection_dict['server_src'] = connection.server.transport.getPeer()

			#Set ProxyServer Destination IP, PORT
			connection_dict['server_dst'] = connection.server.transport.getHost()

			#Set ProxyClient Source IP, PORT
			connection_dict['client_src'] = connection.client.transport.getHost()

			#Set ProxyClient Destination IP, PORT
			connection_dict['client_dst'] = connection.client.transport.getPeer()

			#SSL information
			connection_dict['client_ssl_info'] = connection.client.transport.getHandle()

			connection_dict['dst_str'] = "{}_{}".format(connection.client.transport.getPeer().host, connection.client.transport.getPeer().port)


		elif connection.__class__.__name__ in ["ProxyServer", "ProxyClient"]:
			connection_dict['socket_protocol'] = 'tcp'

			if connection.__class__.__name__ == "ProxyServer":
				client = connection.peer
				server = connection
			else:
				server = connection.peer
				client = connection				

			#Set ProxyServer Source IP, PORT
			connection_dict['server_src'] = server.transport.getPeer()

			#Set ProxyServer Destination IP, PORT
			connection_dict['server_dst'] = server.transport.getHost()

			#Set ProxyClient Source IP, PORT
			connection_dict['client_src'] = client.transport.getHost()

			#Set ProxyClient Destination IP, PORT
			connection_dict['client_dst'] = client.transport.getPeer()

			connection_dict['dst_str'] = "{}_{}".format(client.transport.getPeer().host, client.transport.getPeer().port)

		elif connection.__class__.__name__ in ["UDPProxyClient", "UDPProxyServer"]:
			connection_dict['socket_protocol'] = 'udp'

			#Set ProxyServer Source IP, PORT
			connection_dict['server_src'] = (connection.server.proxyserver_srchost, connection.server.proxyserver_srcport)

			#Set ProxyServer Destination IP, PORT
			connection_dict['server_dst'] = (connection.server.listenhost, connection.server.listenport)

			#Set ProxyClient Source IP, PORT
			#connection_dict['client_src'] = (connection.proxyclient_srchost, connection.proxyclient_dstport)

			#Set ProxyClient Destination IP, PORT
			connection_dict['client_dst'] = (connection.server.client_dsthost, connection.server.client_dstport)

			connection_dict['dst_str'] = "{}_{}".format(connection.server.client_dsthost, connection.server.client_dstport)

		return connection_dict

	def on_server2client_done_read(self, connection, data):
		#Set Common Varables in dictionary
		connection_dict = self.common_info(connection)
		#print(connection_dict)

		#Check if printable
		try:
			if self.log_folder:
				with open("{}/{}/{}_{}_dst".format(self.log_folder, connection_dict['dst_str'], int(time.time()*100000), connection_dict['socket_protocol']), "wb") as f:
					f.write(data)
			if self.verbose:
				data_string = data.decode('utf8')
				if all(c in string.printable for c in data_string):
					print("#{}:C<-S ({} bytes):\n{}".format(self.connid, len(data), data_string))
				else: 
					print("#{}:C<-S ({} bytes):\n{}".format(self.connid, len(data), hexdump(data)) )
		except Exception as e:
			if self.verbose:
				print("#{}:C<-S ({} bytes):\n{}".format(self.connid, len(data), hexdump(data)) )
		
		#Add Callback to Change Return Data here
		return data
		
	def on_client2server_done_read(self, connection, data):
		#Set Common Varables in dictionary
		connection_dict = self.common_info(connection)
		#print(connection_dict)

		try:
			if self.log_folder:
				if not os.path.exists(self.log_folder + "/" + connection_dict['dst_str']):
					os.makedirs(self.log_folder + "/" + connection_dict['dst_str'])		

				with open("{}/{}/{}_{}_src".format(self.log_folder, connection_dict['dst_str'], int(time.time()*100000), connection_dict['socket_protocol']), "wb") as f:
					f.write(data)
			if self.verbose:
				data_string = data.decode('utf8')
				if all(c in string.printable for c in data_string):
					print("#{}:C->S ({} bytes):\n{}".format(self.connid, len(data), data_string))
				else: 
					print("#{}:C->S ({} bytes):\n{}".format(self.connid, len(data), hexdump(data)) )
			
		except Exception as e:
			print(e)
			if self.verbose:
				print("#{}:C->S ({} bytes):\n{}".format(self.connid, len(data), hexdump(data)) )
		
		#Add Callback to Change Sending Data here
		return data

	def on_server2client_new_connection(self, connection):
		print("#{}: New Connection to destination {}".format(self.connid, connection))

	def on_client2server_new_connection(self, connection):
		print("#{}: New Connection on local server {}".format(self.connid, connection))
		self.connid +=1

	def on_server2client_close_connection(self, connection, reason):
		print("#{}: Server closed connection".format(self.connid))

	def on_client2server_close_connection(self, connection, reason):
		print("#{}: Client closed connected".format(self.connid))

