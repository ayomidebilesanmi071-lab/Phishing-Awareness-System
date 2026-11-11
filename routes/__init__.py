"""Route helpers shared by all blueprints."""

from functools import wraps

from flask import abort, redirect, request, url_for
from flask_login import current_user


def role_required(*roles):
    """Decorator enforcing role-based access control.

    * Anonymous users are redirected to the login page.
    * Authenticated users without one of the allowed roles get a 403.
    """

    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return redirect(url_for("auth.login", next=request.full_path))
            if not current_user.has_role(*roles):
                abort(403)
            return fn(*args, **kwargs)

        return wrapper

    return decorator


def home_for(user):
    """Return the dashboard endpoint for a user's role."""
    return {
        "employee": "employee.dashboard",
        "analyst": "analyst.dashboard",
        "admin": "admin.dashboard",
    }.get(user.role, "awareness.articles")


def register_blueprints(app):
    """Register every route blueprint on the application."""
    from routes.admin import admin_bp
    from routes.analyst import analyst_bp
    from routes.auth import auth_bp
    from routes.awareness import awareness_bp
    from routes.employee import employee_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(employee_bp)
    app.register_blueprint(analyst_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(awareness_bp)
