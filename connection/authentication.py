class DefaultAuth:
    def __init__(self):
        self.encrypt = lambda string: string
        self.success = bytes([0x02])
        self.error = bytes([0x03])
        self.pending = bytes([0x01])

    def wrap_credentials(self, username: str, password: str):
        pap_request = self.pending + bytes([len(username)])
        pap_request += username.encode() + bytes([len(password)])
        return pap_request + password.encode()

    def unpack_credentials(self, packet):
        password = 3 + packet[1] + packet[2 + packet[1]]
        username = packet[2:2+packet[1]].decode()
        password = packet[3 + packet[1]:password]
        return username, password.decode()

    def check_credentials(self, credentials, packet):
        username, password = self.unpack_credentials(packet)
        check1 = credentials[0] == username
        check2 = credentials[1] == self.encrypt(password)
        return self.success if check1 and check2 else self.error
