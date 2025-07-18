import hashlib
import time
import datetime

from pathlib import Path
from flask import Blueprint, request, Flask, render_template, url_for, redirect, flash, jsonify
from CTFd.models import db, Flags, Teams
from CTFd.utils.user import (
    get_ip,
    get_user_attrs,
    get_current_user,
)
from CTFd.utils.decorators import authed_only, admins_only
from CTFd.plugins.flags import get_flag_class, FlagException
from CTFd.utils.config import get_config, is_teams_mode

from .models import DynamicFlag, cheatList

online = Blueprint('detecter', __name__, template_folder="templates", url_prefix='/detecter')

def is_team_mode():
    return is_teams_mode()

def insert_dynamic_flag(challenge_id, created_flag, flag_type):
    add_flag = Flags(
        challenge_id=challenge_id,
        type=flag_type if flag_type is not None else "static",
        content=created_flag,
        data=""
    )
    db.session.add(add_flag)
    db.session.commit()

def handle_team_mode_cheating(check_info, user_id, user_name, user_team):
    sharer_name = get_user_attrs(check_info.user_id).name
    sharer_team = Teams.query.filter_by(id=check_info.team_id).first()
    
    if user_team and sharer_team and user_team.id != sharer_team.id:
        print("Cheat Hit - Cross Team")
        print("Sharer Team: ", sharer_team.name)
        print("Sharer: ", sharer_name)
        print("Shared Team: ", user_team.name)
        print("Shared: ", user_name)
        
        add_log = cheatList(
            shared_username=sharer_name,
            sharer_username=user_name,
            shared_team=user_team.name,
            sharer_team=sharer_team.name,
            cheat_ip=get_ip(),
            timestamp=int(time.time()),
            reason="Cross Team Flag Sharing"
        )
        
        db.session.add(add_log)
        db.session.commit()
        return True
    return False

def handle_individual_mode_cheating(check_info, user_id, user_name, user_team):
    sharer_name = get_user_attrs(check_info.user_id).name
    sharer_team = Teams.query.filter_by(id=check_info.team_id).first()
    
    print("Cheat Hit - Individual")
    print("Sharer: ", sharer_name)
    print("Shared: ", user_name)
    
    add_log = cheatList(
        shared_username=sharer_name,
        sharer_username=user_name,
        shared_team=user_team.name if user_team else "Individual",
        sharer_team=sharer_team.name if sharer_team else "Individual",
        cheat_ip=get_ip(),
        timestamp=int(time.time()),
        reason="Flag Sharing"
    )
    
    db.session.add(add_log)
    db.session.commit()
    return True

def cheat_detecter(submission):
    user_id = get_current_user().id
    user_name = get_user_attrs(user_id).name
    user_team = Teams.query.filter_by(id=get_current_user().team_id).first()
    
    check_info = DynamicFlag.query.filter_by(created_flag=submission).first()
    if check_info and user_id != check_info.user_id:
        if is_team_mode():
            return handle_team_mode_cheating(check_info, user_id, user_name, user_team)
        else:
            return handle_individual_mode_cheating(check_info, user_id, user_name, user_team)
    return False

@online.route('/api/cheat_data', methods=['GET'])
@admins_only
def route_cheat_data():
    cheatusers = cheatList.query.order_by(cheatList.timestamp.desc()).all()
    data = [{
        'shared_username': c.shared_username, 
        'sharer_username': c.sharer_username,
        'shared_team': c.shared_team,
        'sharer_team': c.sharer_team,
        'cheat_ip': c.cheat_ip, 
        'timestamp': c.timestamp, 
        'reason': c.reason
    } for c in cheatusers]
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
    from .docker_monitor import start_monitor
    start_monitor(app)
    
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
