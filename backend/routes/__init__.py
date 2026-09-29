from backend.routes import health, history, model, prediction

BLUEPRINTS = (health.bp, prediction.bp, history.bp, model.bp)
