from __future__ import annotations

from functools import wraps

from flask import jsonify
from flask_login import current_user


def require_roles(*roles: str):
    normalized = {role.lower() for role in roles}

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not current_user.is_authenticated:
                return jsonify({"error": "authentication required"}), 401

            user_role = (getattr(current_user, "role", "") or "").lower()
            if user_role not in normalized:
                return jsonify({"error": "forbidden", "requiredRoles": sorted(normalized)}), 403

            return func(*args, **kwargs)

        return wrapper

    return decorator
