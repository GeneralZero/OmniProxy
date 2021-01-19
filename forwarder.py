from twisted.internet import reactor
from twisted.internet import ssl
from twisted.protocols import portforward
from twisted.internet import task

from twisted.internet import protocol
from twisted.python import log
import sys

#log.startLogging(sys.stdout)

##Foward data from Proxy to => Remote Server
class SSLProxyClient(protocol.Protocol):
	def connectionMade(self):
		#log.msg("SSLProxyClient.connectionMade")
		self.server.setClient(self)
		self.client = self
		
		self.transport.registerProducer(self.server.transport, True)
		self.server.transport.unregisterProducer()
		self.server.transport.registerProducer(self.transport, True)

		# We're connected, everybody can read to their hearts content.
		self.server.transport.resumeProducing()

	def dataReceived(self, data):
		#log.msg("SSLProxyClient.dataReceived:")
		if self.server is not None:
			self.server.transport.write(data)
	
	def connectionLost(self, reason):
		#log.msg("SSLProxyClient.connectionLost")
		if self.server is not None:
			self.server.transport.loseConnection()
			self.server = None
		elif self.noisy:
			#log.msg("Unable to connect to peer: {}".format(reason))
			pass

	def setServer(self, server):
		#log.msg("SSLProxy.setPeer")
		self.server = server

class SSLProxyClientFactory(protocol.ClientFactory):
	protocol = SSLProxyClient

	def setServer(self, server):
		#log.msg("SSLProxyClientFactory.setServer")
		self.server = server

	def buildProtocol(self, *args, **kw):
		#log.msg("SSLProxyClientFactory.buildProtocol")
		prot = protocol.ClientFactory.buildProtocol(self, *args, **kw)
		prot.setServer(self.server)
		return prot

	def clientConnectionFailed(self, connector, reason):
		#log.msg("SSLProxyClientFactory.clientConnectionFailed")
		self.server.transport.loseConnection()

#Proxy Server Class
class SSLProxyServer(protocol.Protocol):
	clientProtocolFactory = SSLProxyClientFactory
	reactor = None

	def connectionMade(self):
		#log.msg("SSLProxyServer.connectionMade")
		self.server = self

		#Get Current SSL Context
		ssl_context = self.transport._tlsConnection.get_context()

		#Hack to get SNI to do two functions in diffrent classes
		ssl_context._server_context = self

	def SNICallback(self, connection):
		#log.msg("SSLProxyServer.SNICallback: {}".format(connection))
		#print(connection.get_context().new_host)

		#self.transport.pauseProducing()
		self.dst_host, self.dst_port = connection.get_context().new_host

		#print("Setting Up Clients")
		#Setup Clients
		self.client = self.clientProtocolFactory()
		self.client.setServer(self)

		if self.reactor is None:
			self.reactor = reactor

		self.reactor.connectSSL(self.dst_host, self.dst_port, self.client, self.factory.clientContextFactory)

	#Client -> Proxy
	def dataReceived(self, data):
		#log.msg("SSLProxyServer.dataReceived: {}".format(data))
		if self.client is not None:
			self.client.transport.write(data)

	def connectionLost(self, reason):
		#log.msg("SSLProxyServer.connectionLost")
		if self.client is not None:
			self.client.transport.loseConnection()
			self.client = None
		elif self.noisy:
			#log.msg("Unable to connect to peer: {}".format(reason))
			pass

	def setClient(self, client):
		#log.msg("SSLProxyServer.setClient")
		self.client = client


class SSLProxyFactory(protocol.Factory):
	"""Factory for port forwarder."""
	protocol = SSLProxyServer

	def __init__(self, clientContextFactory):
		#log.msg("SSLProxyFactory.__init__")
		self.clientContextFactory = clientContextFactory


class UDPProxyClient(protocol.DatagramProtocol):
	noisy = False
	def __init__(self, server, src_host, src_port, dst_host, dst_port):
		self.server = server
		self.client = self

		self.server_srchost = src_host
		self.server_srcport = src_port

		self.client_dsthost = dst_host
		self.client_dstport = dst_port

	def datagramReceived(self, data, hostAndPort):
		#log.msg("UDPProxyClient.datagramReceived: [{}]  {}".format(hostAndPort, data))
		#Received From Destination Server
		#Sending back to origional Client
		self.server.transport.write(data, (self.server_srchost, self.server_srcport))
		self.server.removeRoute("".format(self.server_srchost, self.server_srcport))
		self.transport.loseConnection()


class UDPProxyServer(protocol.DatagramProtocol):
	noisy = False
	def __init__(self, localhost, localport, host, port):
		#log.msg("UDPProxyServer.__init__: {}:{}".format(host, port))
		self.server = self

		self.listenhost = localhost
		self.listenport = localport

		self.client_dsthost = host
		self.client_dstport = port

		self.route_table = {}

	def removeRoute(self, socket_key):
		route = self.route_table.pop(socket_key, None)

	def datagramReceived(self, data, hostAndPort):
		#log.msg("UDPProxyServer.datagramReceived: [{}]  {}".format(hostAndPort, data))

		#Get Host Info
		socket_key = "{}:{}".format(self.proxyserver_srchost, self.proxyserver_srcport)

		#Inital Connection
		if socket_key not in self.route_table:
			proxyclient = UDPProxyClient(self, self.proxyserver_srchost, self.proxyserver_srcport, self.client_dsthost, self.client_dstport)
			self.route_table[socket_key] = proxyclient
			#self.route_table[socket_key]
			proxy_socket = reactor.listenUDP(0, proxyclient)
			proxyclient.srchost = proxy_socket.getHost().host
			proxyclient.srcport = proxy_socket.getHost().port


		self.route_table[socket_key].transport.write(data, (self.client_dsthost, self.client_dstport))


#Creating inital Proxyies
def tcpToTcp(localhost, localport, remotehost, remoteport):
	#log.msg("TCP on {}:{} forwarding to TCP {}:{}".format(localhost, localport, remotehost, remoteport))
	return reactor.listenTCP(localport, portforward.ProxyFactory(remotehost, remoteport), interface=localhost)

def sslToTcp(localhost, localport, remotehost, remoteport, serverContextFactory):
	#log.msg("SSL on {}:{} forwarding to TCP {}:{}".format(localhost, localport, remotehost, remoteport))
	return reactor.listenSSL(localport, portforward.ProxyFactory(remotehost, remoteport), serverContextFactory, interface=localhost)


def tcpToSSL(localhost, localport, remotehost, remoteport, clientContextFactory=ssl.ClientContextFactory()):
	#log.msg("TCP on {}:{} forwarding to SSL {}:{}".format(localhost, localport, remotehost, remoteport))
	return reactor.listenTCP(localport, SSLProxyFactory(clientContextFactory), interface=localhost)


def sslToSSL(localhost, localport, remotehost, remoteport, CA, serverContextFactory, clientContextFactory=ssl.ClientContextFactory()):
	#log.msg("SSL on {}:{} forwarding to SSL {}:{}".format(localhost, localport, remotehost, remoteport))
	return reactor.listenSSL(localport, SSLProxyFactory(clientContextFactory), serverContextFactory, interface=localhost)

def udpToUDP(localhost, localport, remotehost, remoteport):
	#log.msg("UDP on {}:{} forwarding to UDP {}:{}".format(localhost, localport, remotehost, remoteport))
	return reactor.listenUDP(localport, UDPProxyServer(localhost, localport, remotehost, remoteport), interface=localhost)


#Setting Callbacks on Receve and Transmit
def setTCPServerReceiveCallback(callback):
	def server_dataReceived(self, data):
		data = callback(self, data)
		portforward.ProxyServer._dataReceived(self, data)

	portforward.ProxyServer._dataReceived = portforward.ProxyServer.dataReceived
	portforward.ProxyServer.dataReceived = server_dataReceived

def setSSLServerReceiveCallback(callback):
	def server_ssl_dataReceived(self, data):
		data = callback(self, data)
		SSLProxyServer._dataReceived(self, data)

	SSLProxyServer._dataReceived = SSLProxyServer.dataReceived
	SSLProxyServer.dataReceived = server_ssl_dataReceived

def setUDPServerReceiveCallback(callback):
	def server_dataReceived(self, data, hostAndPort):
		self.proxyserver_srchost, self.proxyserver_srcport = hostAndPort
		data = callback(self, data)
		UDPProxyServer._datagramReceived(self, data, hostAndPort)

	UDPProxyServer._datagramReceived = UDPProxyServer.datagramReceived
	UDPProxyServer.datagramReceived = server_dataReceived


def setServerReceiveCallback(callback):
	setSSLServerReceiveCallback(callback)
	setTCPServerReceiveCallback(callback)
	setUDPServerReceiveCallback(callback)


def setTCPClientReceiveCallback(callback):
	def client_dataReceived(self, data):
		data = callback(self, data)
		portforward.ProxyClient._dataReceived(self, data)

	portforward.ProxyClient._dataReceived = portforward.ProxyClient.dataReceived
	portforward.ProxyClient.dataReceived = client_dataReceived

def setSSLClientReceiveCallback(callback):
	def client_ssl_dataReceived(self, data):
		data = callback(self, data)
		SSLProxyClient._dataReceived(self, data)

	SSLProxyClient._dataReceived = SSLProxyClient.dataReceived
	SSLProxyClient.dataReceived = client_ssl_dataReceived

def setUDPClientReceiveCallback(callback):
	def client_dataReceived(self, data, hostAndPort):
		self.server_source = hostAndPort
		data = callback(self, data)
		UDPProxyClient._datagramReceived(self, data, hostAndPort)

	UDPProxyClient._datagramReceived = UDPProxyClient.datagramReceived
	UDPProxyClient.datagramReceived = client_dataReceived

def setClientReceiveCallback(callback):
	setSSLClientReceiveCallback(callback)
	setTCPClientReceiveCallback(callback)
	setUDPClientReceiveCallback(callback)



def setTCPClientStartCallback(callback):
	def client_connectionMade(self):
		callback(self)
		portforward.ProxyClient._connectionMade(self)

	portforward.ProxyClient._connectionMade = portforward.ProxyClient.connectionMade
	portforward.ProxyClient.connectionMade = client_connectionMade

def setSSLClientStartCallback(callback):
	def client_ssl_connectionMade(self):
		callback(self)
		SSLProxyClient._connectionMade(self)

	SSLProxyClient._connectionMade = SSLProxyClient.connectionMade
	SSLProxyClient.connectionMade = client_ssl_connectionMade

def setUDPPClientStartCallback(callback):
	def client_connectionMade(self):
		callback(self)
		portforward.ProxyClient._connectionMade(self)

	portforward.ProxyClient._connectionMade = portforward.ProxyClient.connectionMade
	portforward.ProxyClient.connectionMade = client_connectionMade

def setClientStartCallback(callback):
	setSSLClientStartCallback(callback)
	setTCPClientStartCallback(callback)


def setTCPServerStartCallback(callback):
	def server_connectionMade(self):
		callback(self)
		portforward.ProxyServer._connectionMade(self)

	portforward.ProxyServer._connectionMade = portforward.ProxyServer.connectionMade
	portforward.ProxyServer.connectionMade = server_connectionMade

def setSSLServerStartCallback(callback):
	def server_ssl_connectionMade(self):
		callback(self)
		SSLProxyServer._connectionMade(self)

	SSLProxyServer._connectionMade = SSLProxyServer.connectionMade
	SSLProxyServer.connectionMade = server_ssl_connectionMade

def setServerStartCallback(callback):
	setSSLServerStartCallback(callback)
	setTCPServerStartCallback(callback)



def setTCPServerCloseCallback(callback):
	def server_connectionLost(self, reason):
		callback(self, reason)
		portforward.ProxyServer._connectionLost(self, reason)

	portforward.ProxyServer._connectionLost = portforward.ProxyServer.connectionLost
	portforward.ProxyServer.connectionLost  = server_connectionLost

def setSSLServerCloseCallback(callback):
	def server_ssl_connectionLost(self, reason):
		callback(self, reason)
		SSLProxyServer._connectionLost(self, reason)

	SSLProxyServer._connectionLost = SSLProxyServer.connectionLost
	SSLProxyServer.connectionLost = server_ssl_connectionLost

def setServerCloseCallback(callback):
	setSSLServerCloseCallback(callback)
	setTCPServerCloseCallback(callback)

def setTCPClientCloseCallback(callback):
	def client_connectionLost(self, reason):
		callback(self, reason)
		portforward.ProxyClient._connectionLost(self, reason)

	portforward.ProxyClient._connectionLost = portforward.ProxyClient.connectionLost
	portforward.ProxyClient.connectionLost = client_connectionLost

def setSSLClientCloseCallback(callback):
	def client_ssl_connectionLost(self, reason):
		callback(self, reason)
		SSLProxyClient._connectionLost(self, reason)

	SSLProxyClient._connectionLost = SSLProxyClient.connectionLost
	SSLProxyClient.connectionLost = client_ssl_connectionLost

def setClientCloseCallback(callback):
	setSSLClientCloseCallback(callback)
	setTCPClientCloseCallback(callback)
