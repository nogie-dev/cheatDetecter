import hashlib
from flask import session
from CTFd.models import db

from CTFd.utils.user import (
    get_ip, 
    get_user_attrs,
    get_current_user,
    get_current_user_attrs
)
from CTFd.models import Flags
from .models import DynamicFlag

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
            #team_id=safe_team_id,
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
    print(check_info)
    if check_info:
        if user_id != check_info.id:
             print(get_user_attrs(2))
             sharer_name = get_user_attrs(check_info.user_id).name
             print(sharer_name)
             print("Cheater!!!")
             print("Sharer : ", sharer_name)
             print("Shared : ", user_name)
             return True
    
def load(app):
    app.db.create_all()

        

