add_executable(real-socket-client real-socket-client.cpp utils-socket.h)
add_executable(real-socket-server real-socket-server.cpp utils-socket.h)

#add_executable(pre-server-sockets pre-server.cpp pre-socket-utils.h )
#add_executable(pre-client-sockets pre-client.cpp pre-socket-utils.h )
#target_compile_options(pre-server-sockets PUBLIC -DUSE_SOCKETS)

add_executable(tcp-echo-client tcp_echo_client.cpp)
add_executable(tcp-echo-server tcp_echo_server.cpp)

add_executable(chat-server chat_server.cpp chat_message.hpp)
add_executable(chat-client chat_client.cpp chat_message.hpp)

