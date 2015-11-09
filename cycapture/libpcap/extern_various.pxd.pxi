# -*- coding: utf-8 -*-

# cdef extern from "sys/types.h":
#     struct sockaddr:
#         unsigned char sa_family
#         unsigned char sa_len
#         char sa_data[14]
#     struct in_addr:
#         unsigned int s_addr
#     struct in6_addr:
#         pass
#     struct sockaddr_in:
#         unsigned char sin_len
#         in_addr sin_addr
#     struct sockaddr_in6:
#         unsigned char sin6_len
#         in6_addr sin6_addr
#
#     enum: INET_ADDRSTRLEN
#     enum: INET6_ADDRSTRLEN
#
# cdef extern from "netdb.h":
#     enum: NI_MAXHOST
#     enum: NI_NUMERICHOST
#     enum: NI_MAXSERV
#     enum: NI_NUMERICSERV
#     int getnameinfo(const sockaddr*, unsigned int, char*, unsigned int, char*, unsigned int, int)
#
# cdef extern from "arpa/inet.h":
#     const char* inet_ntop(int, const void*, char*, unsigned int)

