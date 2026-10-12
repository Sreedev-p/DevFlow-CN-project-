import time

class MetricEngine:
    def __init__(self):
        # Stores request timestamps: {(client_port, server_port): start_time}
        self.active_requests = {}

    def track_request(self, src_port, dest_port):
        # Save the time the request was sent
        self.active_requests[(src_port, dest_port)] = time.time()

    def track_response(self, src_port, dest_port):
        # A response flips the ports (Server is now src, Client is dest)
        req_key = (dest_port, src_port)
        
        if req_key in self.active_requests:
            start_time = self.active_requests.pop(req_key)
            latency_ms = (time.time() - start_time) * 1000
            return round(latency_ms, 2)
        
        return None