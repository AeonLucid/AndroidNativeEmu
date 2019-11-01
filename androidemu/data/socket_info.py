# https://github.com/torvalds/linux/blob/master/include/linux/socket.h
AF_UNIX = 1

# http://students.mimuw.edu.pl/SO/Linux/Kod/include/linux/socket.h.html
SOCK_STREAM = 1


class SocketInfo:

    def __init__(self):
        self.domain = 0
        self.type = 0
        self.protocol = 0
