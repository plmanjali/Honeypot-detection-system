from app import app
from decoy_website import register_decoy_routes

# Register only the decoy website routes (admin routes already registered in app.py)
register_decoy_routes(app)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
