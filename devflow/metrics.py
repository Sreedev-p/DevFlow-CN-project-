import time
import uuid


class MetricEngine:
    def __init__(self):
        # Maps (client_port, server_port) -> {"start": float, "trace_id": str, "proc": str}
        self.active_requests = {}
        # Maps process_info -> {"trace_id": str, "start": float} for linking child DB/TLS spans
        self.active_proc_traces = {}

    def track_request(self, src_port, dest_port, proc_info="Unknown"):
        if len(self.active_requests) > 1000:
            self.active_requests.clear()
            self.active_proc_traces.clear()

        now = time.time()
        trace_id = f"tr-{uuid.uuid4().hex[:8]}"

        self.active_requests[(src_port, dest_port)] = {
            "start": now,
            "trace_id": trace_id,
            "proc": proc_info
        }

        # Associate this process with the active trace so downstream SQL/Redis calls link to it
        if proc_info and proc_info != "Unknown":
            self.active_proc_traces[proc_info] = {
                "trace_id": trace_id,
                "start": now
            }

        return trace_id, 0.0

    def track_child_span(self, proc_info="Unknown"):
        """
        Links a downstream SQL, Redis, or TLS packet to an in-flight HTTP request
        within a 2.5-second window. Returns (trace_id, offset_ms).
        """
        now = time.time()

        # First check exact process match, otherwise fallback to the most recent active request
        trace_meta = self.active_proc_traces.get(proc_info)
        if not trace_meta and self.active_requests:
            latest_req = max(self.active_requests.values(), key=lambda x: x["start"])
            if now - latest_req["start"] <= 2.5:
                trace_meta = latest_req

        if trace_meta and (now - trace_meta["start"] <= 2.5):
            offset_ms = round((now - trace_meta["start"]) * 1000, 2)
            return trace_meta["trace_id"], offset_ms

        return f"tr-{uuid.uuid4().hex[:8]}", 0.0

    def track_response(self, src_port, dest_port):
        """
        Matches the flipped port tuple (server_port, client_port) back to the original HTTP request.
        Returns (latency_ms, trace_id, offset_ms).
        """
        req_key = (dest_port, src_port)

        if req_key in self.active_requests:
            req_data = self.active_requests.pop(req_key)
            latency_ms = round((time.time() - req_data["start"]) * 1000, 2)
            return latency_ms, req_data["trace_id"], latency_ms

        return None, f"tr-{uuid.uuid4().hex[:8]}", 0.0