/**
* @file boost_socks5.cpp
* @brief Simple SOCKS5 proxy server realization using boost::asio library
* @author philave (philave7@gmail.com)
*/

#include <cstdlib>
#include <iostream>
#include <string>
#include <memory>
#include <utility>
#include <boost/asio.hpp>
#include <fstream>
#include "config_reader.hpp"

using boost::asio::ip::tcp;

// Common log function
inline void write_log(int Prefix, short Verbose, short VerboseLevel, int SessionID, const std::string& What, const std::string& ErrorMessage = "")
{
	if (Verbose > VerboseLevel) return;

	std::string session = "";
	if (SessionID >= 0) { session += "session("; session += std::to_string(SessionID); session += "): "; }

	if (Prefix > 0)
	{
		std::cerr << (Prefix == 1 ? "Error: " : "Warning: ") << session << What;
		if (ErrorMessage.size() > 0)
			std::cerr << ": " << ErrorMessage;
		std::cerr << std::endl;
	}
	else
	{ 
		std::cout << session << What;
		if (ErrorMessage.size() > 0)
			std::cout << ": " << ErrorMessage;
		std::cout << std::endl;
	}
}

class Session : public std::enable_shared_from_this<Session>
{
public:
	Session(tcp::socket InSocket, unsigned SessionID, size_t BufferSize, short Verbose)
		:	inSocket(std::move(InSocket)), 
			outSocket(InSocket.get_io_service()), 
			resolver(InSocket.get_io_service()),
			inBuf(BufferSize), 
			outBuf(BufferSize), 
			sessionID(SessionID),
			verbose(Verbose)
	{
	}

	void start()
	{
		read_socks5_handshake();
	}

private:

	void read_socks5_handshake()
	{
		auto self(shared_from_this());

		inSocket.async_receive(boost::asio::buffer(inBuf),
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
/*
The client connects to the server, and sends a version
identifier/method selection message:

+----+----------+----------+
|VER | NMETHODS | METHODS  |
+----+----------+----------+
| 1  |    1     | 1 to 255 |
+----+----------+----------+

The values currently defined for METHOD are:

o  X'00' NO AUTHENTICATION REQUIRED
o  X'01' GSSAPI
o  X'02' USERNAME/PASSWORD
o  X'03' to X'7F' IANA ASSIGNED
o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
o  X'FF' NO ACCEPTABLE METHODS

*/
					if (length < 3 || inBuf[0] != 0x05)
					{
						write_log(1, 0, verbose, sessionID, "SOCKS5 handshake request is invalid. Closing session.");
						return;
					}

					uint8_t num_methods = inBuf[1];
					// Prepare request
					inBuf[1] = 0xFF;

					// Only 0x00 - 'NO AUTHENTICATION REQUIRED' is now supported
					for (uint8_t method = 0; method < num_methods; ++method)
						if (inBuf[2 + method] == 0x00) { inBuf[1] = 0x00; break; }
					
					write_socks5_handshake();
				}
				else
					write_log(1, 0, verbose, sessionID, "SOCKS5 handshake request", ec.message());

			});
	}

	void write_socks5_handshake()
	{
		auto self(shared_from_this());

		inSocket.async_send(boost::asio::buffer(inBuf, 2), // Always 2-byte according to RFC1928
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{	
					if (inBuf[1] == 0xFF) return; // No appropriate auth method found. Close session.
					read_socks5_request();
				}
				else
					write_log(1, 0, verbose, sessionID, "SOCKS5 handshake response write", ec.message());

			});
	}

	void read_socks5_request()
	{
		auto self(shared_from_this());

		inSocket.async_receive(boost::asio::buffer(inBuf),
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
/*
The SOCKS request is formed as follows:

+----+-----+-------+------+----------+----------+
|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Where:

o  VER    protocol version: X'05'
o  CMD
o  CONNECT X'01'
o  BIND X'02'
o  UDP ASSOCIATE X'03'
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  DST.ADDR       desired destination address
o  DST.PORT desired destination port in network octet
order

The SOCKS server will typically evaluate the request based on source
and destination addresses, and return one or more reply messages, as
appropriate for the request type.
*/
					if (length < 5 || inBuf[0] != 0x05 || inBuf[1] != 0x01)
					{
						write_log(1, 0, verbose, sessionID, "SOCKS5 request is invalid. Closing session.");
						return;
					}

					uint8_t addr_type = inBuf[3], host_length;

					switch (addr_type)
					{
					case 0x01: // IP V4 addres
						if (length != 10) { write_log(1, 0, verbose, sessionID, "SOCKS5 request length is invalid. Closing session."); return; }
						remoteHost = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&inBuf[4]))).to_string();
						remotePort = std::to_string(ntohs(*((uint16_t*)&inBuf[8])));
						break;
					case 0x03: // DOMAINNAME
						host_length = inBuf[4];
						if (length != (size_t)(5 + host_length + 2)) { write_log(1, 0, verbose, sessionID, "SOCKS5 request length is invalid. Closing session."); return; }
						remoteHost = std::string(&inBuf[5], host_length);
						remotePort = std::to_string(ntohs(*((uint16_t*)&inBuf[5 + host_length])));
						break;
					default:
						write_log(1, 0, verbose, sessionID, "unsupported address type in SOCKS5 request. Closing session.");
						break;
					}

					do_resolve();
				}
				else
					write_log(1, 0, verbose, sessionID, "SOCKS5 request read", ec.message());

			});
	}

	void do_resolve()
	{
		auto self(shared_from_this());

		resolver.async_resolve(tcp::resolver::query({ remoteHost, remotePort }),
			[this, self](const boost::system::error_code& ec, tcp::resolver::iterator it)
			{
				if (!ec)
				{
					do_connect(it);
				}
				else
				{
					std::ostringstream what; what << "failed to resolve " << remoteHost << ":" << remotePort;
					write_log(1, 0, verbose, sessionID, what.str(), ec.message());
				}
			});
	}

	void do_connect(tcp::resolver::iterator& it)
	{
		auto self(shared_from_this());
		outSocket.async_connect(*it, 
			[this, self](const boost::system::error_code& ec)
			{
				if (!ec)
				{
					std::ostringstream what; what << "connected to " << remoteHost << ":" << remotePort;
					write_log(0, 1, verbose, sessionID, what.str());
					write_socks5_response();
				}
				else
				{
					std::ostringstream what; what << "failed to connect " << remoteHost << ":" << remotePort;
					write_log(1, 0, verbose, sessionID, what.str(), ec.message());

				}
			});

	}

	void write_socks5_response()
	{
		auto self(shared_from_this());

/*
The SOCKS request information is sent by the client as soon as it has
established a connection to the SOCKS server, and completed the
authentication negotiations.  The server evaluates the request, and
returns a reply formed as follows:

+----+-----+-------+------+----------+----------+
|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
+----+-----+-------+------+----------+----------+
| 1  |  1  | X'00' |  1   | Variable |    2     |
+----+-----+-------+------+----------+----------+

Where:

o  VER    protocol version: X'05'
o  REP    Reply field:
o  X'00' succeeded
o  X'01' general SOCKS server failure
o  X'02' connection not allowed by ruleset
o  X'03' Network unreachable
o  X'04' Host unreachable
o  X'05' Connection refused
o  X'06' TTL expired
o  X'07' Command not supported
o  X'08' Address type not supported
o  X'09' to X'FF' unassigned
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  BND.ADDR       server bound address
o  BND.PORT       server bound port in network octet order

Fields marked RESERVED (RSV) must be set to X'00'.
*/
		inBuf[0] = 0x05; inBuf[1] = 0x00; inBuf[2] = 0x00; inBuf[3] = 0x01;
		uint32_t realRemoteIP = outSocket.remote_endpoint().address().to_v4().to_ulong();
		uint16_t realRemotePort = htons(outSocket.remote_endpoint().port());

		std::memcpy(&inBuf[4], &realRemoteIP, 4);
		std::memcpy(&inBuf[8], &realRemotePort, 2);

		inSocket.async_send(boost::asio::buffer(inBuf, 10), // Always 10-byte according to RFC1928
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					do_read(3); // Read both sockets
				}
				else
					write_log(1, 0, verbose, sessionID, "SOCKS5 response write", ec.message());
			});
	}


	void do_read(int Direction)
	{
		auto self(shared_from_this());

		// We must divide reads by direction to not permit second read call on the same socket.
		if (Direction & 0x1)
			inSocket.async_receive(boost::asio::buffer(inBuf),
				[this, self](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
					{
						std::ostringstream what; what << "--> " << std::to_string(length) << " bytes";
						write_log(0, 2, verbose, sessionID, what.str());

						do_write(1, length);
					}
					else //if (ec != boost::asio::error::eof)
					{
						write_log(2, 1, verbose, sessionID, "closing session. Client socket read error", ec.message());
						// Most probably client closed socket. Let's close both sockets and exit session.
						inSocket.close(); outSocket.close();
					}

				});

		if (Direction & 0x2)
			outSocket.async_receive(boost::asio::buffer(outBuf),
				[this, self](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
					{
						std::ostringstream what; what << "<-- " << std::to_string(length) << " bytes";
						write_log(0, 2, verbose, sessionID, what.str());

						do_write(2, length);
					}
					else //if (ec != boost::asio::error::eof)
					{
						write_log(2, 1, verbose, sessionID, "closing session. Remote socket read error", ec.message());
						// Most probably remote server closed socket. Let's close both sockets and exit session.
						inSocket.close(); outSocket.close();
					}
				});
	}

	void do_write(int Direction, std::size_t Length)
	{
		auto self(shared_from_this());

		switch (Direction)
		{
		case 1:
			outSocket.async_send(boost::asio::buffer(inBuf, Length),
				[this, self, Direction](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
						do_read(Direction);
					else
					{
						write_log(2, 1, verbose, sessionID, "closing session. Client socket write error", ec.message());
						// Most probably client closed socket. Let's close both sockets and exit session.
						inSocket.close(); outSocket.close();
					}
				});
			break;
		case 2:
			inSocket.async_send(boost::asio::buffer(outBuf, Length),
				[this, self, Direction](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
						do_read(Direction);
					else
					{
						write_log(2, 1, verbose, sessionID, "closing session. Remote socket write error", ec.message());
						// Most probably remote server closed socket. Let's close both sockets and exit session.
						inSocket.close(); outSocket.close();
					}
				});
			break;
		}
	}

	tcp::socket inSocket;
	tcp::socket outSocket;
	tcp::resolver resolver;

	std::string remoteHost;
	std::string remotePort;
	std::vector<char> inBuf;
	std::vector<char> outBuf;
	int sessionID;
	short verbose;
};

class Server
{
public:
	Server(boost::asio::io_service& IOService, short Port, unsigned BufferSize, short Verbose)
		: acceptor(IOService, tcp::endpoint(tcp::v4(), Port)), 
		inSocket(IOService), bufferSize(BufferSize), verbose(Verbose), sessionID(0)
	{
		do_accept();
	}

private:
	void do_accept()
	{
		acceptor.async_accept(inSocket,
			[this](boost::system::error_code ec)
			{
				if (!ec)
				{
					std::make_shared<Session>(std::move(inSocket), sessionID++, bufferSize, verbose)->start();
				}
				else
					write_log(1, 0, verbose, sessionID, "socket accept error", ec.message());

				do_accept();
			});
	}

	tcp::acceptor acceptor;
	tcp::socket inSocket;
	size_t bufferSize;
	short verbose;
	unsigned sessionID;
};

int main(int argc, char* argv[])
{
	short verbose = 0;
	try
	{
		if (argc != 2)
		{
			std::cout << "Usage: boost_socks5 <config_file>" << std::endl;
			return 1;
		}

		ConfigReader conf;
		conf.Parse(argv[1]);

		short port = conf.CheckKey("port") ? std::atoi(conf.GetKeyValue("port")) : 1080; // Default port
		size_t bufferSize = conf.CheckKey("buffer_size") ? std::atoi(conf.GetKeyValue("buffer_size")) : 8192; // Default buffer_size
		verbose = conf.CheckKey("verbose") ? std::atoi(conf.GetKeyValue("verbose")) : 0; // Default verbose

		boost::asio::io_service ioService;
		Server server(ioService, port, bufferSize, verbose);
		ioService.run();
	}
	catch (std::exception& e)
	{
		write_log(1, 0, verbose, -1, "", e.what());
	}
	catch (...)
	{
		write_log(1, 0, verbose, -1, "", "exception...");
	}

	return 0;
}