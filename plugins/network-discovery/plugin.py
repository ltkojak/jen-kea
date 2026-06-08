"""
Network Discovery plugin for Jen.
Registers the network_discovery blueprint.
"""
from flask import Blueprint, render_template, jsonify
from flask_login import login_required

bp = Blueprint("network_discovery", __name__,
               template_folder="templates",
               url_prefix="/network/discovery")


@bp.route("/")
@login_required
def index():
    return render_template("network_discovery/index.html")


@bp.route("/api/status")
@login_required
def status():
    return jsonify({"status": "Network Discovery plugin loaded", "version": "0.1.0"})


def register(app):
    app.register_blueprint(bp)
