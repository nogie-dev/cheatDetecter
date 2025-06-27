import threading
import docker
import hashlib
from datetime import datetime
from .models import db, ContainerLog, DynamicFlag
from CTFd.utils.config import is_teams_mode

def generate_flag_from_container(container_id):
    """Generate a flag based on container ID"""
    concat_str = str(container_id) + str("tmp")
    return hashlib.sha256(concat_str.encode()).hexdigest()

def monitor_docker_events(app):
    print("[cheatDetecter] Docker event monitor started!")
    try:
        client = docker.from_env()
    except Exception as e:
        print("[cheatDetecter] Docker client init error:", e)
        return
    for event in client.events(decode=True):
        if event.get('Type') == 'container' and event.get('Action') == 'create':
            container_id = event.get('id')
            try:
                container = client.containers.get(container_id)
                user_id = container.labels.get('ctfd_user_id')
                challenge_id = container.labels.get('ctfd_challenge_id')
                team_id = container.labels.get('ctfd_team_id')
                user_ip = container.labels.get('ctfd_user_ip')
                
                print(f"[cheatDetecter] Logging container: {container_id}, user_id: {user_id}, challenge_id: {challenge_id}")
                
                with app.app_context():
                    # Check if we're in team mode
                    is_team = is_teams_mode()
                    
                    # Generate flag from container ID
                    flag = generate_flag_from_container(container_id)
                    
                    # Log container creation
                    container_log = ContainerLog(
                        container_id=container_id,
                        user_id=user_id,
                        challenge_id=challenge_id,
                        created_at=datetime.utcnow()
                    )
                    db.session.add(container_log)
                    
                    # Log flag creation (DynamicFlag) - handle team_id based on mode
                    flag_log = DynamicFlag(
                        created_flag=flag,
                        container_id=container_id,
                        challenge_id=challenge_id,
                        user_id=user_id,
                        team_id=team_id if is_team else None,  # Only set team_id in team mode
                        user_ip=user_ip
                    )
                    db.session.add(flag_log)
                    
                    # Insert flag into CTFd's Flags table
                    from CTFd.models import Flags
                    ctfd_flag = Flags(
                        challenge_id=challenge_id,
                        type="static",
                        content=flag,
                        data=""
                    )
                    db.session.add(ctfd_flag)
                    db.session.commit()
                    print(f"[cheatDetecter] Successfully logged container and flag: {flag} (Team mode: {is_team})")
                    
            except Exception as e:
                print("[cheatDetecter] DB Error:", e)

def start_monitor(app):
    t = threading.Thread(target=monitor_docker_events, args=(app,), daemon=True)
    t.start() 