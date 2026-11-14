import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app

class FixPath:
    def __init__(self, wsgi_app):
        self.wsgi_app = wsgi_app
    def __call__(self, environ, start_response):
        path = environ.get('PATH_INFO', '')
        if path.startswith('/api/index.py'):
            path = path[len('/api/index.py'):] or '/'
            environ['PATH_INFO'] = path
        return self.wsgi_app(environ, start_response)

app.wsgi_app = FixPath(app.wsgi_app)