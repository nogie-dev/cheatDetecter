from sqlalchemy.sql import func
from sqlalchemy.orm import relationship

from CTFd.models import db
from CTFd.models import Challenges
import datetime


class DynamicFlag(db.Model):
    id = db.Column(
        db.Integer, primary_key=True
    )

    created_flag = db.Column(db.Text)
    container_id = db.Column(db.Text)
    challenge_id = db.Column(db.Integer)
    team_id = db.Column(db.Integer, nullable=True)
    user_id = db.Column(db.Integer)
    user_ip = db.Column(db.Text)

    def __init__(self, *args, **kwargs):
        super(DynamicFlag, self).__init__(**kwargs)


class cheatList(db.Model):
    id = db.Column(
        db.Integer, primary_key=True
    )

    shared_username = db.Column(db.Text)
    sharer_username = db.Column(db.Text)
    shared_team = db.Column(db.Text)
    sharer_team = db.Column(db.Text)
    cheat_ip = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.Integer)
    reason = db.Column(db.Text)

    def __init__(self, *args, **kwargs):
        super(cheatList, self).__init__(**kwargs)