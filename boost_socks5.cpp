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
inline void write_log(int prefix, short verbose, short verbose_level, int session_id, const std::string& what, const std::string& error_message = "")
{
	if (verbose > verbose_level) return;

	std::string session = "";
	if (session_id >= 0) { session += "session("; session += std::to_string(session_id); session += "): "; }

	if (prefix > 0)
	{
		std::cerr << (prefix == 1 ? "Error: " : "Warning: ") << session << what;
		if (error_message.size() > 0)
			std::cerr << ": " << error_message;
		std::cerr << std::endl;
	}
	else
	{ 
		std::cout << session << what;
		if (error_message.size() > 0)
			std::cout << ": " << error_message;
		std::cout << std::endl;
	}
}

class Session : public std::enable_shared_from_this<Session>
{
public:
	Session(tcp::socket in_socket, unsigned session_id, size_t buffer_size, short verbose)
		:	in_socket_(std::move(in_socket)), 
			out_socket_(in_socket.get_io_service()), 
			resolver(in_socket.get_io_service()),
			in_buf_(buffer_size), 
			out_buf_(buffer_size), 
			session_id_(session_id),
			verbose_(verbose)
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

		in_socket_.async_receive(boost::asio::buffer(in_buf_),
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
					if (length < 3 || in_buf_[0] != 0x05)
					{
						write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake request is invalid. Closing session.");
						return;
					}

					uint8_t num_methods = in_buf_[1];
					// Prepare request
					in_buf_[1] = 0xFF;

					// Only 0x00 - 'NO AUTHENTICATION REQUIRED' is now support_ed
					for (uint8_t method = 0; method < num_methods; ++method)
						if (in_buf_[2 + method] == 0x00) { in_buf_[1] = 0x00; break; }
					
					write_socks5_handshake();
				}
				else
					write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake request", ec.message());

			});
	}

	void write_socks5_handshake()
	{
		auto self(shared_from_this());

		boost::asio::async_write(in_socket_, boost::asio::buffer(in_buf_, 2), // Always 2-byte according to RFC1928
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{	
					if (in_buf_[1] == 0xFF) return; // No appropriate auth method found. Close session.
					read_socks5_request();
				}
				else
					write_log(1, 0, verbose_, session_id_, "SOCKS5 handshake response write", ec.message());

			});
	}

	void read_socks5_request()
	{
		auto self(shared_from_this());

		in_socket_.async_receive(boost::asio::buffer(in_buf_),
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
o  DST.PORT desired destination port_ in network octet
order

The SOCKS server will typically evaluate the request based on source
and destination addresses, and return one or more reply messages, as
appropriate for the request type.
*/
					if (length < 5 || in_buf_[0] != 0x05 || in_buf_[1] != 0x01)
					{
						write_log(1, 0, verbose_, session_id_, "SOCKS5 request is invalid. Closing session.");
						return;
					}

					uint8_t addr_type = in_buf_[3], host_length;

					switch (addr_type)
					{
					case 0x01: // IP V4 addres
						if (length != 10) { write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return; }
						remote_host_ = boost::asio::ip::address_v4(ntohl(*((uint32_t*)&in_buf_[4]))).to_string();
						remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf_[8])));
						break;
					case 0x03: // DOMAINNAME
						host_length = in_buf_[4];
						if (length != (size_t)(5 + host_length + 2)) { write_log(1, 0, verbose_, session_id_, "SOCKS5 request length is invalid. Closing session."); return; }
						remote_host_ = std::string(&in_buf_[5], host_length);
						remote_port_ = std::to_string(ntohs(*((uint16_t*)&in_buf_[5 + host_length])));
						break;
					default:
						write_log(1, 0, verbose_, session_id_, "unsupport_ed address type in SOCKS5 request. Closing session.");
						break;
					}

					do_resolve();
				}
				else
					write_log(1, 0, verbose_, session_id_, "SOCKS5 request read", ec.message());

			});
	}

	void do_resolve()
	{
		auto self(shared_from_this());

		resolver.async_resolve(tcp::resolver::query({ remote_host_, remote_port_ }),
			[this, self](const boost::system::error_code& ec, tcp::resolver::iterator it)
			{
				if (!ec)
				{
					do_connect(it);
				}
				else
				{
					std::ostringstream what; what << "failed to resolve " << remote_host_ << ":" << remote_port_;
					write_log(1, 0, verbose_, session_id_, what.str(), ec.message());
				}
			});
	}

	void do_connect(tcp::resolver::iterator& it)
	{
		auto self(shared_from_this());
		out_socket_.async_connect(*it, 
			[this, self](const boost::system::error_code& ec)
			{
				if (!ec)
				{
					std::ostringstream what; what << "connected to " << remote_host_ << ":" << remote_port_;
					write_log(0, 1, verbose_, session_id_, what.str());
					write_socks5_response();
				}
				else
				{
					std::ostringstream what; what << "failed to connect " << remote_host_ << ":" << remote_port_;
					write_log(1, 0, verbose_, session_id_, what.str(), ec.message());

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
o  X'07' Command not support_ed
o  X'08' Address type not support_ed
o  X'09' to X'FF' unassigned
o  RSV    RESERVED
o  ATYP   address type of following address
o  IP V4 address: X'01'
o  DOMAINNAME: X'03'
o  IP V6 address: X'04'
o  BND.ADDR       server bound address
o  BND.PORT       server bound port_ in network octet order

Fields marked RESERVED (RSV) must be set to X'00'.
*/
		in_buf_[0] = 0x05; in_buf_[1] = 0x00; in_buf_[2] = 0x00; in_buf_[3] = 0x01;
		uint32_t realRemoteIP = out_socket_.remote_endpoint().address().to_v4().to_ulong();
		uint16_t realRemoteport = htons(out_socket_.remote_endpoint().port());

		std::memcpy(&in_buf_[4], &realRemoteIP, 4);
		std::memcpy(&in_buf_[8], &realRemoteport, 2);

		boost::asio::async_write(in_socket_, boost::asio::buffer(in_buf_, 10), // Always 10-byte according to RFC1928
			[this, self](boost::system::error_code ec, std::size_t length)
			{
				if (!ec)
				{
					do_read(3); // Read both sockets
				}
				else
					write_log(1, 0, verbose_, session_id_, "SOCKS5 response write", ec.message());
			});
	}


	void do_read(int direction)
	{
		auto self(shared_from_this());

		// We must divide reads by direction to not permit second read call on the same socket.
		if (direction & 0x1)
			in_socket_.async_receive(boost::asio::buffer(in_buf_),
				[this, self](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
					{
						std::ostringstream what; what << "--> " << std::to_string(length) << " bytes";
						write_log(0, 2, verbose_, session_id_, what.str());

						do_write(1, length);
					}
					else //if (ec != boost::asio::error::eof)
					{
						write_log(2, 1, verbose_, session_id_, "closing session. Client socket read error", ec.message());
						// Most probably client closed socket. Let's close both sockets and exit session.
						in_socket_.close(); out_socket_.close();
					}

				});

		if (direction & 0x2)
			out_socket_.async_receive(boost::asio::buffer(out_buf_),
				[this, self](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
					{
						std::ostringstream what; what << "<-- " << std::to_string(length) << " bytes";
						write_log(0, 2, verbose_, session_id_, what.str());

						do_write(2, length);
					}
					else //if (ec != boost::asio::error::eof)
					{
						write_log(2, 1, verbose_, session_id_, "closing session. Remote socket read error", ec.message());
						// Most probably remote server closed socket. Let's close both sockets and exit session.
						in_socket_.close(); out_socket_.close();
					}
				});
	}

	void do_write(int direction, std::size_t Length)
	{
		auto self(shared_from_this());

		switch (direction)
		{
		case 1:
			boost::asio::async_write(out_socket_, boost::asio::buffer(in_buf_, Length),
				[this, self, direction](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
						do_read(direction);
					else
					{
						write_log(2, 1, verbose_, session_id_, "closing session. Client socket write error", ec.message());
						// Most probably client closed socket. Let's close both sockets and exit session.
						in_socket_.close(); out_socket_.close();
					}
				});
			break;
		case 2:
			boost::asio::async_write(in_socket_, boost::asio::buffer(out_buf_, Length),
				[this, self, direction](boost::system::error_code ec, std::size_t length)
				{
					if (!ec)
						do_read(direction);
					else
					{
						write_log(2, 1, verbose_, session_id_, "closing session. Remote socket write error", ec.message());
						// Most probably remote server closed socket. Let's close both sockets and exit session.
						in_socket_.close(); out_socket_.close();
					}
				});
			break;
		}
	}

	tcp::socket in_socket_;
	tcp::socket out_socket_;
	tcp::resolver resolver;

	std::string remote_host_;
	std::string remote_port_;
	std::vector<char> in_buf_;
	std::vector<char> out_buf_;
	int session_id_;
	short verbose_;
};

class Server
{
public:
	Server(boost::asio::io_service& io_service, short port, unsigned buffer_size, short verbose)
		: acceptor_(io_service, tcp::endpoint(tcp::v4(), port)), 
		in_socket_(io_service), buffer_size_(buffer_size), verbose_(verbose), session_id_(0)
	{
		do_accept();
	}

private:
	void do_accept()
	{
		acceptor_.async_accept(in_socket_,
			[this](boost::system::error_code ec)
			{
				if (!ec)
				{
					std::make_shared<Session>(std::move(in_socket_), session_id_++, buffer_size_, verbose_)->start();
				}
				else
					write_log(1, 0, verbose_, session_id_, "socket accept error", ec.message());

				do_accept();
			});
	}

	tcp::acceptor acceptor_;
	tcp::socket in_socket_;
	size_t buffer_size_;
	short verbose_;
	unsigned session_id_;
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
		conf.parse(argv[1]);

		short port = conf.check_key("port") ? std::atoi(conf.get_key_value("port")) : 1080; // Default port_
		size_t buffer_size = conf.check_key("buffer_size") ? std::atoi(conf.get_key_value("buffer_size")) : 8192; // Default buffer_size
		verbose = conf.check_key("verbose") ? std::atoi(conf.get_key_value("verbose")) : 0; // Default verbose_

		boost::asio::io_service io_service;
		Server server(io_service, port, buffer_size, verbose);
		io_service.run();
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