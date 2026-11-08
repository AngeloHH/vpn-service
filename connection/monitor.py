import threading
import time


class SpeedMonitor:
    def __init__(self):
        self.transferred = [0, 0]
        self.speed = [0, 0]
        self.lock = threading.Lock()

    def check_speed(self):
        while True:
            download, upload = self.transferred
            time.sleep(1)
            with self.lock:
                self.speed[0] = self.transferred[0] - download
                self.speed[1] = self.transferred[1] - upload

    def start_monitoring(self):
        speed_thread = threading.Thread(target=self.check_speed)
        speed_thread.daemon = True
        speed_thread.start()

    def update_transfer(self, download_bytes, upload_bytes):
        with self.lock:
            self.transferred[0] += download_bytes
            self.transferred[1] += upload_bytes
