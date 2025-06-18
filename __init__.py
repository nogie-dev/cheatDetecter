# __init__.py for cheatDetecter plugin
import hashlib
import time
import datetime

from pathlib import Path
from flask import Blueprint, request, Flask, render_template, url_for, redirect, flash, jsonify
from CTFd.models import db, Flags
from CTFd.utils.user import (
    get_ip,
    get_user_attrs,
    get_current_user,
)
from CTFd.utils.decorators import authed_only, admins_only
from CTFd.plugins.flags import get_flag_class, FlagException

# Import the models for the plugin
from .models import DynamicFlag, cheatList

online = Blueprint('detecter', __name__, template_folder="templates", url_prefix='/detecter')

def insert_dynamic_flag(challenge_id, created_flag, flag_type):
    add_flag = Flags(
        challenge_id=challenge_id,
        type=flag_type if flag_type is not None else "static",
        content=created_flag,
        data=""
    )
    db.session.add(add_flag)
    db.session.commit()

def flag_created_log(container_id, chal_id, team_id, user_id):
    concat_str = str(container_id) + str("tmp")
    hashing_flag = hashlib.sha256(concat_str.encode()).hexdigest()
    add_log = DynamicFlag(
        created_flag=hashing_flag,
        container_id=container_id,
        challenge_id=chal_id,
        user_id=user_id,
        user_ip=get_ip()
    )
    flag_type=None
    insert_dynamic_flag(chal_id, hashing_flag, flag_type)
    
    db.session.add(add_log)
    db.session.commit()

def cheat_detecter(submission):
    user_id=get_current_user().id
    user_name = get_user_attrs(user_id).name
    check_info = DynamicFlag.query.filter_by(created_flag=submission).first()
    if check_info:
        if user_id != check_info.user_id:
            sharer_name = get_user_attrs(check_info.user_id).name
            print("Cheat Hit")
            print("Sharer : ", sharer_name)
            print("Shared : ", user_name)
            
            add_log = cheatList(
                shared_username=sharer_name,
                sharer_username=user_name,
                cheat_ip=get_ip(),
                timestamp=int(time.time()),
                reason="Flag Sharing"
            )
            
            db.session.add(add_log)
            db.session.commit()
            return True
    return False

@online.route('/api/cheat_data', methods=['GET'])
@admins_only
def route_cheat_data():
    cheatusers = cheatList.query.order_by(cheatList.timestamp.desc()).all()
    data = [{'shared_username': c.shared_username, 'sharer_username': c.sharer_username, 'cheat_ip': c.cheat_ip, 'timestamp': c.timestamp, 'reason': c.reason} for c in cheatusers]
    return jsonify(data)

@online.app_template_filter("format_time")
def format_time_filter(unix_seconds):
    dt = datetime.datetime.fromtimestamp(unix_seconds, tz=datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo)
    return dt.strftime("%H:%M:%S %d/%m/%Y")

@online.route('/dashboard',methods=['GET'])
@admins_only
def show_cheat():
    if request.method == 'GET':
        cheats = cheatList.query.all()
        return render_template('cheat_dashboard.html',cheats=cheats)

def load(app):
    from CTFd.plugins.challenges import BaseChallenge, CHALLENGE_CLASSES
    
    original_attempt = BaseChallenge.attempt
    
    @classmethod
    def attempt_with_cheat_detection(cls, challenge, request):
        data = request.form or request.get_json()
        submission = data.get("submission", "").strip()

        if cheat_detecter(submission):
            return False, "Cheating detected! This flag has been shared."
        
        return original_attempt(cls, challenge, request)
    
    BaseChallenge.attempt = attempt_with_cheat_detection
    
    app.db.create_all()
    app.register_blueprint(online)
    
    CHALLENGE_CLASSES["cheat_detecter"] = BaseChallenge
