from flask import request, session
from user_agents import parse
import logging
from datetime import datetime
import os
import json

# Global variable for GeoIP status
GEOIP_ENABLED = False
try:
    import geoip2.database
    from geoip2.errors import AddressNotFoundError
    GEOIP_ENABLED = True
except ImportError:
    pass

class SecurityLogger:
    def __init__(self, app):
        self.app = app
        self.geo_reader = None
        
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.makedirs('logs')

        # Configure main logger
        logging.basicConfig(level=logging.INFO)
        
        # Create file handler for access logs
        self.access_logger = logging.getLogger('access_log')
        self.access_logger.setLevel(logging.INFO)
        self.access_logger.propagate = False
        access_handler = logging.FileHandler('logs/access.log')
        access_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(message)s')
        )
        self.access_logger.addHandler(access_handler)
        
        # Create file handler for security logs
        self.security_logger = logging.getLogger('security_log')
        self.security_logger.setLevel(logging.WARNING)
        self.security_logger.propagate = False
        security_handler = logging.FileHandler('logs/security.log')
        security_handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        self.security_logger.addHandler(security_handler)

        # Initialize GeoIP reader if available
        if GEOIP_ENABLED:
            try:
                db_path = os.path.join(os.path.dirname(__file__), 'GeoLite2-City.mmdb')
                if os.path.exists(db_path):
                    self.geo_reader = geoip2.database.Reader(db_path)
                else:
                    # Change from warning to debug to prevent console output
                    self.app.logger.debug(f"GeoIP database not found at {db_path}")
            except Exception:
                # Silently continue with default location_info if GeoIP lookup fails
                pass

    def get_client_info(self):  # <-- Fixed indentation, moved out of __init__
        """Get detailed client information including Cloudflare headers"""
        user_agent_string = request.headers.get('User-Agent', '')
        user_agent = parse(user_agent_string)
        
        # Get IP address - try different headers
        ip = (request.headers.get('CF-Connecting-IP') or 
              request.headers.get('X-Real-IP') or 
              request.headers.get('X-Forwarded-For', '').split(',')[0].strip() or 
              request.remote_addr)
        
        # Initialize location info
        location_info = {
            'country': request.headers.get('CF-IPCountry', 'unknown'),
            'city': request.headers.get('CF-IPCity', 'unknown'),
            'isp': request.headers.get('CF-Connecting-ISP', 'unknown'),
            'latitude': 'unknown',
            'longitude': 'unknown',
            'timezone': 'unknown',
            'subdivision': 'unknown'
        }
        
        # Try to get location info from GeoIP
        if self.geo_reader and GEOIP_ENABLED:
            try:
                geo = self.geo_reader.city(ip)
                location_info.update({
                    'country': geo.country.name,
                    'city': geo.city.name or 'unknown',
                    'latitude': str(geo.location.latitude),
                    'longitude': str(geo.location.longitude),
                    'timezone': geo.location.time_zone,
                    'subdivision': geo.subdivisions.most_specific.name if geo.subdivisions else 'unknown',
                    'continent': geo.continent.name
                })
            except AddressNotFoundError:
                # Silently continue with default location_info
                pass
            except Exception:
                # Silently handle any other exceptions
                pass


        # Try to parse CF-Visitor header
        try:
            cf_visitor = json.loads(request.headers.get('CF-Visitor', '{}'))
            scheme = cf_visitor.get('scheme', 'http')
        except json.JSONDecodeError:
            scheme = 'http'

        # Complete client info structure
        client_info = {
            'access_details': {
                'ip': ip,
                'location': location_info,
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'ray_id': request.headers.get('CF-RAY', 'unknown')
            },
            'user_info': {
                'username': session.get('username', 'anonymous'),
                'name': session.get('name', 'unknown'),
                'department': session.get('department', 'none'),
                'is_admin': session.get('is_admin', False)
            },
            'device_info': {
                'type': user_agent.device.family,
                'browser': f"{user_agent.browser.family} {user_agent.browser.version_string}",
                'os': f"{user_agent.os.family} {user_agent.os.version_string}",
                'is_mobile': user_agent.is_mobile,
                'is_tablet': user_agent.is_tablet
            },
            'request_info': {
                'method': request.method,
                'path': request.path,
                'referrer': request.referrer or 'direct',
                'protocol': scheme
            }
        }

        return client_info

    def log_access(self, response=None):
        """Log access with detailed client information"""
        info = self.get_client_info()
        if response:
            info['response'] = {
                'status': response.status_code,
                'size': response.content_length
            }
        
        log_message = self.format_log_message(info)
        self.access_logger.info(log_message)
        return info

    def log_security_event(self, event_type, details):
        """Log security-related events"""
        info = self.get_client_info()
        log_message = self.format_log_message(info, event_type, details)
        self.security_logger.warning(log_message)
        return info

    def format_log_message(self, info, event_type=None, details=None):
        """Format log message for better readability"""
        access = info['access_details']
        user = info['user_info']
        device = info['device_info']
        req = info['request_info']
        loc = access['location']
        
        base_msg = (
            f"IP: {access['ip']} | "
            f"Location: {loc['city']}, {loc['country']} ({loc.get('subdivision', 'unknown')}) | "
            f"Coords: {loc['latitude']},{loc['longitude']} | "  # Added coordinates
            f"ISP: {loc['isp']} | "
            f"User: {user['username']} ({user['department']}) | "
            f"{req['method']} {req['path']} | "
            f"Browser: {device['browser']} | "
            f"OS: {device['os']}"
        )

        if event_type:
            base_msg = f"EVENT: {event_type} | " + base_msg
            if details:
                base_msg += f" | Details: {json.dumps(details)}"

        return base_msg