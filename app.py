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
        "https://YOUR_NETLIFY_APP.netlify.app",   # ← update with real URL after Netlify deploy
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:5000",
        "http://127.0.0.1:5000",
    ])

    from routes.upload import upload_bp
    from routes.fetch  import fetch_bp
    from routes.verify import verify_bp

    app.register_blueprint(upload_bp, url_prefix='/api')
    app.register_blueprint(fetch_bp,  url_prefix='/api')
    app.register_blueprint(verify_bp, url_prefix='/api')

    return app


app = create_app()

if __name__ == '__main__':
    app.run(debug=False, port=5000)
