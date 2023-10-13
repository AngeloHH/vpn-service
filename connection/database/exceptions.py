class AddressConflict(Exception):
    def __init__(self, ip_address: str = None):
        self.ip_address = ip_address

    def already_defined(self):
        text = 'The ip address{} has already been assigned.'
        if self.ip_address:
            text = text.format(' ' + self.ip_address)
        return super().__init__(text.format('')) or self
