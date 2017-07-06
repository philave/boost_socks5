# boost_socks5 proxy server

## Description
This is simple realization of socks5 proxy server according to the [RFC 1928](https://www.ietf.org/rfc/rfc1928.txt) using `boost::asio` library. The server uses async socket calls for data forwarding and io_service for message processing. Currently, boost_socks5 proxy server works only in `NO AUTHENTICATION REQUIRED` mode.

## Build
The proxy server build was tested with boost version 1.58. However, earlier versions of boost will probably work as well.

### Linux
To build on Linux install Boost library and run the following command:
```
g++ -Wall -std=c++11 boost_socks5.cpp -o boost_socks5 -lboost_system -lboost_thread -lpthread
```
### Windows 

#### To build on Windows (mingw-w64)
Run the following command:
```
g++ -Wall -std=c++11 -I <Path_to_Boost_Include> boost_socks5.cpp -o boost_socks5 -static -L <Path_to_Boost_Libs> -lboost_system -lboost_thread -lwsock32 -lws2_32
```
Ignore Boost std::auto_ptr warnings if any.

#### To build on Windows (MS Visual Studio)
Run ‘Developer Command Prompt for VS2015’ and use the following command:
```
cl /EHsc /MD /I <Path_to_Boost_Include> /Feboost_socks5.exe boost_socks5.cpp /link /LIBPATH: <Path_to_Boost_Libs>
```
