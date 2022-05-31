import binascii
import ipaddress
import math
import socket
import threading
import struct
import time
from sys import argv

MODE = {1: 'DISCOVERY', 2: 'OFFER', 3: 'REQUEST', 4: 'ACKNOWLEDGE', 5: 'Send', 8: 'Location', 9: 'Broadcast'}
MAX_FILESIZE = 4096
RESERVE = b'\x00\x00\x00'


def calculate_subnet_range(ip_full):
    portion = ip_full.split("/")[1]
    subnet_range = pow(2, (32-int(portion))) - 2
    return subnet_range


def break_message(message):
    source_ip = message[:4]  # Source IP address (bytes)
    dest_ip = message[4:8]  # Destination IP address (bytes)
    reserve = message[8:11]  # Reverse
    mode = int.from_bytes(message[11:12], byteorder='big')  # Mode number (int)
    assign_ip = message[12:]  # Assigned IP address (bytes)
    return source_ip, dest_ip, reserve, mode, assign_ip


def break_message_distance(message):
    source_ip = message[:4]  # Source IP address (bytes)
    dest_ip = message[4:8]  # Destination IP address (bytes)
    reserve = message[8:11]  # Reverse
    mode = int.from_bytes(message[11:12], byteorder='big')  # Mode number (int)
    target_ip = message[12:16]  # target IP address (bytes)
    distance = message[16:]  # Distance

    return source_ip, dest_ip, reserve, mode, target_ip, distance


def find_mode(message):
    mode = int.from_bytes(message[11:12], byteorder='big')
    return mode


def byte_str2bin(bytestring):
    byte_int = int.from_bytes(bytestring, byteorder='big')
    byte_bin = bin(byte_int)[2:].zfill(32)
    return byte_bin


def ip_to_int(addr):
    return int(ipaddress.IPv4Address(addr))


def int_to_ip(addr):
    return socket.inet_ntoa(struct.pack("!I", addr))


def bin_str2byte(binstring):
    byte_str = int(binstring, 2).to_bytes(4, byteorder='big')
    return byte_str


def int2bytes(value, length):
    return int(value).to_bytes(length, byteorder='big')


def calculate_distance(xy1, xy2):
    distance = math.sqrt((xy1[0]-xy2[0])**2 + (xy1[1]-xy2[1])**2)
    return int(distance)


def package_offer(source_ip, dest_ip, reserve, assign_ip, address, server):
    mode = b'\x02'
    send_Package = source_ip + dest_ip + reserve + mode + assign_ip
    server.sendto(send_Package, address)


def package_discovery(address):
    empty_byte_4 = b'\x00\x00\x00\x00'
    empty_byte_3 = RESERVE
    mode = b'\x01'
    send_Package = empty_byte_4 + empty_byte_4 + empty_byte_3 + mode + empty_byte_4
    return send_Package


def package_ack(source_ip, dest_ip, reserve, assign_ip, address, server):
    mode = b'\x04'
    send_Package = source_ip + assign_ip + reserve + mode + assign_ip
    server.sendto(send_Package, address)


class LocalSwitch:
    def __init__(self, swich_type, ip, sub_postion, latitute, longitude, subnets):
        self.server = None
        self.type = swich_type
        self.ip = ip
        self.subnet_portion = sub_postion
        self.subnets = subnets
        self.latitute = latitute
        self.longitude = longitude
        self.connect = {}

    def take_input(self):
        while True:
            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError as e:
                return
            else:
                self.send_command(user_input)

    def send_command(self, user_input):
        user_input_split = user_input.split(' ')  # prevent splitting data
        comment = user_input_split[0]
        port = user_input_split[1]

        if comment == 'connect':
            theard1 = threading.Thread(target=self.tcp_send, args=(port,))
            theard1.start()

    def tcp_send(self, port):

        # TCP USER SERVER
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.connect(('127.0.0.1', int(port)))
        tcp_socket.sendall(package_discovery(int(port)))

        # Waiting for responses
        while True:
            message = tcp_socket.recv(MAX_FILESIZE)
            mode = find_mode(message)

                # if MODE.get(mode) != 'Send':
                #     self.tcp_greeting(message, tcp_socket)

            if MODE.get(mode) == 'Location':
                source_ip, dest_ip, reserve, mode, location = break_message(message)
                latitude = int.from_bytes(location[:2], byteorder='big')
                longitude = int.from_bytes(location[2:], byteorder='big')
                distance = calculate_distance((latitude, longitude), (int(self.latitute), int(self.longitude)))
                if len(self.connect) > 0:
                    broadcast(self.connect, source_ip, distance, tcp_socket)
                # Save location
                self.connect[source_ip] = [dest_ip, source_ip, distance, tcp_socket]
                print("> ", end='', flush=True)

            elif MODE.get(mode) == 'Broadcast':
                source_ip, dest_ip, reserve, mode, target_ip, distance = break_message_distance(message)
                distance = int.from_bytes(distance, byteorder='big')
                broadcast(self.connect, target_ip, distance, tcp_socket)

                if distance < 1000:
                    if self.connect.get(target_ip) is None:
                        self.connect[target_ip] = [dest_ip, source_ip, distance, tcp_socket]
                    elif self.connect.get(target_ip)[2] > distance:
                        self.connect[target_ip] = [dest_ip, source_ip, distance, tcp_socket]

                print("> ", end='', flush=True)

            elif MODE.get(mode) not in ['Send', 'Location']:
                self.tcp_greeting(message, tcp_socket)

    def tcp_greeting(self, message, connect):
        source_ip, dest_ip, reserve, mode, assign_ip = break_message(message)
        if MODE.get(mode) == 'OFFER':
            mode = b'\x03'
            send_Package = dest_ip + source_ip + reserve + mode + assign_ip
            connect.sendall(send_Package)

        elif MODE.get(mode) == 'ACKNOWLEDGE':
            source_ip, dest_ip, reserve, mode, location = break_message(message)
            mode = b'\x08'
            send_Package = dest_ip + source_ip + reserve + mode + int2bytes(self.latitute, 2) + int2bytes(
                self.longitude, 2)
            connect.send(send_Package)

    # Greeting to Adaptor (UDP)
    def greeting(self, message, address):
        source_ip, dest_ip, reserve, mode, assign_ip = break_message(message)
        if MODE.get(mode) == 'DISCOVERY':
            max_subnet_number = self.subnets[0]
            assign_ip = int_to_ip(self.subnets[1] + 1)
            self.subnets[1] = self.subnets[1] + 1
            assign_ip = socket.inet_aton(assign_ip)

            package_offer(self.ip, source_ip, reserve, assign_ip, address, self.server)

        elif MODE.get(mode) == 'REQUEST':
            package_ack(self.ip, source_ip, reserve, assign_ip, address, self.server)

    def run(self):
        # Create UDP server
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        print(server.getsockname()[1], flush=True)
        self.server = server

        thread_stdin = threading.Thread(target=self.take_input)
        thread_stdin.start()

        while True:
            # Listen the Port and receive package
            bytesAddressPair = self.server.recvfrom(MAX_FILESIZE)
            message = bytesAddressPair[0]
            address = bytesAddressPair[1]
            mode = find_mode(message)

            if MODE.get(mode) != 'Send':
                self.greeting(message, address)


def package_distance(connect, target_ip, distance):
    mode = b'\x09'
    server = connect[3]
    distance = connect[2] + distance
    source_ip = connect[0]
    dest_ip = connect[1]
    send_Package = source_ip + dest_ip + RESERVE + mode + target_ip + int2bytes(distance, 4)
    server.send(send_Package)


def broadcast(original_connect, target_ip, distance, server):
    for connect_socket in original_connect.values():
        if connect_socket[3] != server:
            package_distance(connect_socket, target_ip, distance)


class GlobalSwitch:
    def __init__(self, swich_type, ip, sub_postion, latitute, longitude, subnets):
        self.server = None
        self.type = swich_type
        self.ip = ip
        self.subnet_portion = sub_postion
        self.subnets = subnets
        self.latitute = latitute
        self.longitude = longitude
        self.connect = {}

    def take_input(self):
        """
        Take command from stdin. Acceptable command is 'send'
        """
        while True:
            print('> ', end='', flush=True)
            try:
                user_input = input()
            except EOFError as e:
                return
            else:
                self.send_command(user_input)

    def send_command(self, user_input):
        user_input_split = user_input.split(' ')  # prevent splitting data
        comment = user_input_split[0]
        port = user_input_split[1]

        if comment == 'connect' and int(port) != self.server.getsockname()[1]:
            theard1 = threading.Thread(target=self.tcp_send, args=(port,))
            theard1.start()
        else:
            return

    def tcp_send(self, port):
        tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp_socket.connect(('127.0.0.1', int(port)))
        tcp_socket.send(package_discovery(int(port)))

        while True:
            message = tcp_socket.recv(MAX_FILESIZE)
            if message != b'':
                mode = find_mode(message)
                if MODE.get(mode) == 'Location':
                    source_ip, dest_ip, reserve, mode, location = break_message(message)
                    latitude = int.from_bytes(location[:2], byteorder='big')
                    longitude = int.from_bytes(location[2:], byteorder='big')
                    distance = calculate_distance((latitude, longitude), (int(self.latitute), int(self.longitude)))
                    if len(self.connect) > 0:
                        broadcast(self.connect, source_ip, distance, tcp_socket)
                    # Save location
                    self.connect[source_ip] = [dest_ip, source_ip, distance, tcp_socket]
                    print("> ", end='', flush=True)

                elif MODE.get(mode) == 'Broadcast':
                    source_ip, dest_ip, reserve, mode, target_ip, distance = break_message_distance(message)
                    distance = int.from_bytes(distance, byteorder='big')
                    broadcast(self.connect, target_ip, distance, tcp_socket)

                    if distance < 1000:
                        if self.connect.get(target_ip) is None:
                            self.connect[target_ip] = [dest_ip, source_ip, distance, tcp_socket]
                        elif self.connect.get(target_ip)[2] > distance:
                            self.connect[target_ip] = [dest_ip, source_ip, distance, tcp_socket]

                    print("> ", end='', flush=True)

                elif MODE.get(mode) not in ['Send', 'Location']:
                    self.tcp_greeting(message, tcp_socket)

    def save_location_distance(self, message, connect):
        source_ip, dest_ip, reserve, mode, target_ip, distance = break_message_distance(message)
        self.connect[target_ip] = [dest_ip, source_ip, distance, connect]
        return

    def tcp_location(self, message, connect):
        source_ip, dest_ip, reserve, mode, location = break_message(message)
        mode = b'\x08'
        send_Package = dest_ip + source_ip + reserve + mode + int2bytes(self.latitute, 2) + int2bytes(self.longitude, 2)
        connect.send(send_Package)

    def tcp_greeting(self, message, connect):
        source_ip, dest_ip, reserve, mode, assign_ip = break_message(message)
        if MODE.get(mode) == 'OFFER':
            mode = b'\x03'
            send_Package = b'\x00\x00\x00\x00' + source_ip + reserve + mode + assign_ip
            connect.send(send_Package)

        elif MODE.get(mode) == 'ACKNOWLEDGE':
            self.tcp_location(message, connect)

    def greeting(self, message, address, conn):

        source_ip, dest_ip, reserve, mode, assign_ip = break_message(message)

        if MODE.get(mode) == 'DISCOVERY':
            max_subnet_number = self.subnets[0]
            assign_ip = int_to_ip(self.subnets[1] + 1)
            self.subnets[1] = self.subnets[1] + 1
            assign_ip = socket.inet_aton(assign_ip)

            self.package_offer(self.ip, source_ip, reserve, assign_ip, address, conn)
            return

        elif MODE.get(mode) == 'REQUEST':
            self.package_ack(self.ip, source_ip, reserve, assign_ip, address, conn)
            return

    @staticmethod
    def package_offer(source_ip, dest_ip, reserve, assign_ip, address, connect):
        mode = b'\x02'
        send_Package = source_ip + dest_ip + reserve + mode + assign_ip
        connect.send(send_Package)


    @staticmethod
    def package_ack(source_ip, dest_ip, reserve, assign_ip, address, connect):
        mode = b'\x04'
        send_Package = source_ip + assign_ip + reserve + mode + assign_ip
        connect.send(send_Package)

    def run(self):
        # Create TCP server
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        print(server.getsockname()[1], flush=True)
        self.server = server
        server.listen(5)

        thread_stdin = threading.Thread(target=self.take_input)
        thread_stdin.start()

        while True:
            conn, address = server.accept()

            while True:
                # Listen the Port and receive package
                if conn:
                    data = conn.recv(MAX_FILESIZE)
                    message = data
                    if message != b'':
                        mode = find_mode(message)

                        if MODE.get(mode) == 'Location':
                            source_ip, dest_ip, reserve, mode, location = break_message(message)
                            latitude = int.from_bytes(location[:2], byteorder='big')
                            longitude = int.from_bytes(location[2:], byteorder='big')
                            distance = calculate_distance((latitude, longitude), (int(self.latitute), int(self.longitude)))
                            self.tcp_location(message, conn)
                            self.connect[source_ip] = [dest_ip, source_ip, distance, conn]
                            print("> ", end='', flush=True)

                        elif MODE.get(mode) not in ['Send', 'Location']:
                            self.greeting(message, address, conn)


class LocalGlobalSwitch:
    def __init__(self, swich_type, ip_local, ip_global, sub_postion_local,
                 sub_postion_global, latitute, longitude, subnets_local, subnets_global):
        self.server_local = None
        self.server_global = None
        self.type = swich_type
        self.ip_local = ip_local
        self.ip_global = ip_global
        self.subnet_portion_local = sub_postion_local
        self.subnet_portion_global = sub_postion_global
        self.subnet_list_local = subnets_local
        self.subnet_list_global = subnets_global
        self.latitute = latitute
        self.longitude = longitude
        self.connect = {}

    @staticmethod
    def take_input():
        """
        Take command from stdin. Acceptable command is 'send'
        """
        print('> ', end='', flush=True)

    def tcp_greeting(self, message, address, connect):
        source_ip, dest_ip, reserve, mode, assign_ip = break_message(message)
        if MODE.get(mode) == 'DISCOVERY':
            max_subnet_number = self.subnet_list_global[0]
            assign_ip = int_to_ip(self.subnet_list_global[1] + 1)
            self.subnet_list_global[1] = self.subnet_list_global[1] + 1
            assign_ip = socket.inet_aton(assign_ip)

            self.package_offer_tcp(self.ip_global, source_ip, reserve, assign_ip, address, connect)
            return

        elif MODE.get(mode) == 'REQUEST':
            self.package_ack_tcp(self.ip_global, source_ip, reserve, assign_ip, address, connect)
            return

    def udp_greeting(self, message, address, server):
        source_ip, dest_ip, reserve, mode, assign_ip = break_message(message)

        if MODE.get(mode) == 'DISCOVERY':
            max_subnet_number = self.subnet_list_local[0]
            assign_ip = int_to_ip(self.subnet_list_local[1] + 1)
            self.subnet_list_local[1] = self.subnet_list_local[1] + 1
            assign_ip = socket.inet_aton(assign_ip)

            self.package_offer_udp(self.ip_local, source_ip, reserve, assign_ip, address, server)
            return

        elif MODE.get(mode) == 'REQUEST':
            self.package_ack_udp(self.ip_local, source_ip, reserve, assign_ip, address, server)
            return

    @staticmethod
    def package_offer_tcp(source_ip, dest_ip, reserve, assign_ip, address, connect):
        mode = b'\x02'
        send_Package = source_ip + dest_ip + reserve + mode + assign_ip
        connect.send(send_Package)

    @staticmethod
    def package_ack_tcp(source_ip, dest_ip, reserve, assign_ip, address, connect):
        mode = b'\x04'
        send_Package = source_ip + assign_ip + reserve + mode + assign_ip
        print(send_Package)
        connect.send(send_Package)

    def tcp_location(self, message, connect):
        source_ip, dest_ip, reserve, mode, location = break_message(message)
        mode = b'\x08'
        send_Package = dest_ip + source_ip + reserve + mode + int2bytes(self.latitute, 2) + int2bytes(self.longitude, 2)
        print(send_Package)
        connect.send(send_Package)

    @staticmethod
    def package_offer_udp(source_ip, dest_ip, reserve, assign_ip, address, connect):
        mode = b'\x02'
        send_Package = source_ip + dest_ip + reserve + mode + assign_ip
        connect.sendto(send_Package, address)

    @staticmethod
    def package_ack_udp(source_ip, dest_ip, reserve, assign_ip, address, connect):
        mode = b'\x04'
        send_Package = source_ip + assign_ip + reserve + mode + assign_ip
        connect.sendto(send_Package, address)

    def tcp_listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        print(server.getsockname()[1], flush=True)
        self.server_global = server
        server.listen(5)
        self.take_input()

        while True:
            conn, address = server.accept()

            while True:
                # Listen the Port and receive package
                if conn:
                    data = conn.recv(MAX_FILESIZE)
                    message = data
                    mode = find_mode(message)
                    if MODE.get(mode) == 'Location':
                        source_ip, dest_ip, reserve, mode, location = break_message(message)
                        latitude = int.from_bytes(location[:2], byteorder='big')
                        longitude = int.from_bytes(location[2:], byteorder='big')
                        print('x1 y1: {}  {}, ||  x2 y2:{}  {}'
                              .format(latitude, longitude, int(self.latitute), int(self.longitude)))
                        distance = calculate_distance((latitude, longitude), (int(self.latitute), int(self.longitude)))
                        print('distance:', distance)
                        self.tcp_location(message, conn)
                        # Save location
                        self.connect[source_ip] = [dest_ip, source_ip, distance, conn]
                        package_distance([dest_ip, source_ip, distance, conn], self.ip_local, 0)
                        print("> ", end='', flush=True)

                    elif MODE.get(mode) == 'Broadcast':
                        source_ip, dest_ip, reserve, mode, target_ip, distance = break_message_distance(message)
                        distance = int.from_bytes(distance, byteorder='big')
                        broadcast(self.connect, target_ip, distance, server)

                        if distance < 1000:
                            if self.connect.get(target_ip) is None:
                                self.connect[target_ip] = [dest_ip, source_ip, distance, server]
                            elif self.connect.get(target_ip)[2] > distance:
                                self.connect[target_ip] = [dest_ip, source_ip, distance, server]
                        print("> ", end='', flush=True)

                    elif MODE.get(mode) not in ['Send', 'Location', 'Broadcast']:
                        self.tcp_greeting(message, address, conn)

    def udp_listen(self):
        # Create UDP server
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.bind(("127.0.0.1", 0))
        print(server.getsockname()[1], flush=True)
        self.server_local = server

        while True:
            # Listen the Port and receive package
            bytesAddressPair = self.server_local.recvfrom(MAX_FILESIZE)
            message = bytesAddressPair[0]
            address = bytesAddressPair[1]

            mode = find_mode(message)

            if MODE.get(mode) != 'Send':
                self.udp_greeting(message, address, server)

    def run(self):

        thread1 = threading.Thread(target=self.udp_listen)
        thread1.start()
        time.sleep(0.2)

        thread2 = threading.Thread(target=self.tcp_listen)
        thread2.start()


def main(initial_info):

    # Create Switch
    if len(initial_info) == 5:
        switch_type = initial_info[1]
        latitute = initial_info[3]
        longitude = initial_info[4]
        switch_ip_full = initial_info[2]
        switch_ip, subnet_portion = switch_ip_full.split("/")
        subnet_local_range = calculate_subnet_range(switch_ip_full)
        subnets = [subnet_local_range, ip_to_int(switch_ip)]
        switch_ip_byte = socket.inet_aton(switch_ip)

        if switch_type == 'local':
            switch1 = LocalSwitch(switch_type, switch_ip_byte, subnet_portion, latitute, longitude, subnets)
            thread1 = threading.Thread(target=switch1.run)
            thread1.start()

        elif switch_type == 'global':
            switch2 = GlobalSwitch(switch_type, switch_ip_byte, subnet_portion, latitute, longitude, subnets)
            thread2 = threading.Thread(target=switch2.run)
            thread2.start()

    elif len(initial_info) == 6:
        switch_type = 'local global'
        latitute = initial_info[4]  # Distance x
        longitude = initial_info[5]  # Distance y
        switch_ip_full_local = initial_info[2]  # Local IP address with X
        switch_ip_full_global = initial_info[3]  # Global IP address with X

        switch_ip_local, subnet_portion_local = switch_ip_full_local.split("/")
        subnet_local_range = calculate_subnet_range(switch_ip_full_local)
        subnet_local = [subnet_local_range, ip_to_int(switch_ip_local)]
        local_ip_byte = socket.inet_aton(switch_ip_local)

        switch_ip_global, subnet_portion_global = switch_ip_full_global.split("/")
        subnet_global_range = calculate_subnet_range(switch_ip_full_global)
        subnet_global = [subnet_global_range, ip_to_int(switch_ip_global)]
        global_ip_byte = socket.inet_aton(switch_ip_global)

        # Create Switch thread
        switch3 = LocalGlobalSwitch(switch_type, local_ip_byte, global_ip_byte, subnet_portion_local,
                                    subnet_portion_global, latitute, longitude, subnet_local, subnet_global)
        thread3 = threading.Thread(target=switch3.run)
        thread3.start()


if __name__ == '__main__':
    # RUSHBSwitch('local', '', '', 0, 0).run(argv)
    main(argv)

