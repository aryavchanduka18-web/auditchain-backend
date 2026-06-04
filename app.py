import logging
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s — %(message)s'
)


def create_app():
    app = Flask(__name__)

    CORS(app, origins=[
        "https://auditchain-app.netlify.app",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
    ])

    @app.after_request
    def add_security_headers(response):
        response.headers['X-Content-Type-Options']  = 'nosniff'
        response.headers['X-Frame-Options']          = 'DENY'
        response.headers['Referrer-Policy']          = 'strict-origin-when-cross-origin'
        response.headers['Strict-Transport-Security']= 'max-age=31536000; includeSubDomains'
        # CSP: allow only our own API responses, no scripts/styles served from backend
        response.headers['Content-Security-Policy']  = "default-src 'none'; frame-ancestors 'none'"
        return response

    from routes.upload import upload_bp
    from routes.fetch  import fetch_bp
    from routes.verify import verify_bp
    from routes.fix    import fix_bp

    app.register_blueprint(upload_bp, url_prefix='/api')
    app.register_blueprint(fetch_bp,  url_prefix='/api')
    app.register_blueprint(verify_bp, url_prefix='/api')
    app.register_blueprint(fix_bp,    url_prefix='/api')

    # Global error handlers — never leak stack traces to client
    from flask import jsonify as _jsonify
    @app.errorhandler(404)
    def not_found(e):
        return _jsonify({"error": "Not found.", "code": "NOT_FOUND"}), 404

    @app.errorhandler(405)
    def method_not_allowed(e):
        return _jsonify({"error": "Method not allowed.", "code": "METHOD_NOT_ALLOWED"}), 405

    @app.errorhandler(500)
    def internal_error(e):
        return _jsonify({"error": "Internal server error.", "code": "INTERNAL_ERROR"}), 500

    @app.errorhandler(413)
    def request_too_large(e):
        return _jsonify({"error": "File too large.", "code": "FILE_TOO_LARGE"}), 413

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=False, port=5000)
