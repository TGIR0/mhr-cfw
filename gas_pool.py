import itertools
import time
import logging

logger = logging.getLogger(__name__)

class GasLoadBalancer:
    """
    Manages a pool of Google Apps Script endpoints to bypass daily quota limits (20k req/day).
    Implements Round Robin strategy with quota checking.
    """
    def __init__(self, endpoints):
        if not endpoints:
            raise ValueError("No GAS endpoints provided")
        self.endpoints = endpoints
        self.current_index = 0
        # Track the day of year for daily reset logic
        self.last_reset_day = time.localtime().tm_yday
        logger.info(f"GasLoadBalancer initialized with {len(endpoints)} endpoints.")

    def _check_daily_reset(self):
        """Resets quota counters if a new day has started."""
        current_day = time.localtime().tm_yday
        if current_day != self.last_reset_day:
            logger.info("New day detected. Resetting GAS daily quotas.")
            for ep in self.endpoints:
                ep['daily_quota_used'] = 0
            self.last_reset_day = current_day

    def get_next_endpoint(self):
        """
        Returns the next available endpoint based on Round Robin.
        Raises Exception if all endpoints have exhausted their daily quotas.
        """
        self._check_daily_reset()
        
        # Define daily limit (slightly below 20,000 to be safe)
        DAILY_LIMIT = 19000
        
        # Filter endpoints that haven't reached their limit
        available_endpoints = [
            ep for ep in self.endpoints 
            if ep.get('daily_quota_used', 0) < DAILY_LIMIT
        ]
        
        if not available_endpoints:
            error_msg = "All GAS endpoints have exhausted their daily quotas (Fail-Closed)"
            logger.error(error_msg)
            raise Exception(error_msg)
            
        # Select endpoint using Round Robin on the available list
        # We use modulo on the length of available endpoints to ensure fair distribution
        selected_index = self.current_index % len(available_endpoints)
        endpoint = available_endpoints[selected_index]
        
        self.current_index += 1
        
        # Increment usage counter
        current_usage = endpoint.get('daily_quota_used', 0)
        endpoint['daily_quota_used'] = current_usage + 1
        
        logger.debug(f"Selected GAS endpoint: {endpoint.get('url', 'unknown')} (Usage: {endpoint['daily_quota_used']}/{DAILY_LIMIT})")
        return endpoint

    def get_status(self):
        """Returns a summary of quota usage for all endpoints."""
        self._check_daily_reset()
        status = []
        for i, ep in enumerate(self.endpoints):
            status.append({
                "index": i,
                "url": ep.get('url', 'unknown'),
                "used": ep.get('daily_quota_used', 0),
                "limit": 19000,
                "remaining": 19000 - ep.get('daily_quota_used', 0)
            })
        return status
