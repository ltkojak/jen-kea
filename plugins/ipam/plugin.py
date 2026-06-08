"""
IPAM Lite plugin for Jen.
Registers the ipam blueprint.
"""
from flask import Blueprint, render_template, jsonify
from flask_login import login_required

bp = Blueprint("ipam", __name__,
               template_folder="templates",
               url_prefix="/network/ipam")


@bp.route("/")
@login_required
def index():
    return render_template("ipam/index.html")


@bp.route("/api/status")
@login_required
def status():
    return jsonify({"status": "IPAM Lite plugin loaded", "version": "0.1.0"})


def register(app):
    app.register_blueprint(bp)
