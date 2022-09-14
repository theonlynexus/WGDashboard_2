"""
<WGDashboard 2> - Copyright(C) 2021 Donald Zou [https://github.com/donaldzou], 2022 M. Fierro https://github.com/theonlynexus]
Under Apache-2.0 License
"""

from flask import g
from dashboard import app
from threading import RLock
import sqlite3

_db = None
_cursor = None
_lock = RLock()


def get_db():
    global _db
    return _db

def commit():
    global _db
    _db.commit()

def connect_db(dashboard_configuration_dir: str):
    """
    Connect to the database
    @return: sqlite3.Connection
    """
    import os
    global _db, _cursor

    _db = sqlite3.connect(
        os.path.join(dashboard_configuration_dir, "db", "wgdashboard.db"),
        check_same_thread=False,
    )
    if _db is None:
        raise Exception("Couldn't open database")
    _db.row_factory = sqlite3.Row
    _cursor = _db.cursor()


def execute_locked(q_sql, q_data=None):
    global _db, _cursor

    locked = _lock.acquire()
    if locked:
        try:
            if q_data:
                _cursor.execute(q_sql, q_data)
            else:
                _cursor.execute(q_sql)
            _db.commit()
        finally:
            _lock.release()


def create_peers_table():
    """
    Creates a table for `interface_name`, if missing.
    """

    app.logger.debug(f"db.create_peers_table()")
    create_table = f"""
        CREATE TABLE IF NOT EXISTS peers (
            interface VARCHAR NOT NULL, id VARCHAR NOT NULL, 
            private_key VARCHAR NULL, DNS VARCHAR NULL, 
            endpoint_allowed_ips VARCHAR NULL, name VARCHAR NULL, total_receive FLOAT NULL, 
            total_sent FLOAT NULL, total_data FLOAT NULL, endpoint VARCHAR NULL, 
            status VARCHAR NULL, latest_handshake VARCHAR NULL, allowed_ips VARCHAR NULL, 
            cumu_receive FLOAT NULL, cumu_sent FLOAT NULL, cumu_data FLOAT NULL, mtu INT NULL, 
            keepalive INT NULL, remote_endpoint VARCHAR NULL, preshared_key VARCHAR NULL,
            PRIMARY KEY(interface, id)
        )
    """
    execute_locked(create_table)


def get_peers_with_private_key(interface_name):
    q_sql = """SELECT SELECT private_key, allowed_ips, DNS, mtu, endpoint_allowed_ips, keepalive, preshared_key, name
               FROM peers 
               WHERE interface=:interface_name AND private_key != ''"""
    q_data = {"interface_name": interface_name}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchall()


def get_peer_by_id(interface_name, id):
    """
    Gets basic parameters for a given interface and peer
    """

    q_sql = """SELECT SELECT private_key, allowed_ips, DNS, mtu, endpoint_allowed_ips, keepalive, preshared_key, name
               FROM peers 
               WHERE interface=:interface_name AND id=:id"""
    q_data = {"interface_name": interface_name, "id": id}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchall()


def get_net_stats(interface_name: str) -> list[sqlite3.Row]:
    """
    Gets net stats for all peers of `interface_name` and returns a list of dicts
    """
    app.logger.debug(f"db.get_net_stats({interface_name})")
    q_sql = """SELECT total_sent, total_receive, cumu_sent, cumu_receive 
               FROM peers 
               WHERE interface=:interface_name"""
    q_data = {"interface_name": interface_name}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchall()


def get_allowed_ips_and_endpoint(interface_name):
    q_sql = f"""SELECT id, name, allowed_ips, endpoint 
                FROM peers 
                WHERE interface=:interface_name"""
    q_data = {"interface_name": interface_name}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchall()


def get_net_stats_and_peer_status(interface_name: str, id: str) -> sqlite3.Row | None:
    """
    Gets net stats for a given peer of `interface_name` and the data as `dict`, `None` if not found.
    """
    app.logger.debug(f"db.get_net_stats_and_peer_status({interface_name})")
    q_sql = """SELECT total_receive, total_sent, cumu_receive, cumu_sent, status 
               FROM peers 
               WHERE interface=:interface_name AND id=:id"""
    q_data = {"interface_name": interface_name, "id": id}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchone()


def get_peer_count_by_similar_ip(
    interface_name: str, allowed_ips: str
) -> sqlite3.Row | None:
    q_sql = "SELECT COUNT(*) FROM peers WHERE allowed_ips LIKE :allowed_ips"
    q_data = {"allowed_ips": f"%{allowed_ips}%"}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchone()


def get_peer_count_by_allowed_ips(
    interface_name: str, ip: str, id: str
) -> sqlite3.Row | None:
    """
    Gets and returns the number of peers of `interface_name` that have allowed_ips similar to `ip`.
    """
    app.logger.debug(f"db.get_peer_count_by_allowed_ips({interface_name}, {ip}, {id})")
    q_sql = f"""SELECT COUNT(*) FROM peers
            WHERE interface = :interface_name AND id != :id AND allowed_ips LIKE :ip"""
    q_data = {"id": id, "ip": ip, "interface_name": interface_name}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchone()


def get_peers(interface_name: str, search: str = None) -> list[sqlite3.Row]:
    """Returns the list of records which name matches the search string, or all if no search is provided"""

    app.logger.debug(f"db.get_peers({interface_name}, {search})")
    if search:
        q_sql = f"SELECT * FROM peers WHERE name LIKE :search"
    else:
        q_sql = (
            f"SELECT * FROM peers WHERE interface=:interface_name AND name LIKE :search"
        )
    q_data = {"interface_name": interface_name, "search": f"%{search}%"}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchall()


def get_peer_by_id(interface_name: str, id: str) -> sqlite3.Row | None:
    """
    Returns the peer of `interface_name` matching `id` or None.
    """

    app.logger.debug(f"db.get_peer_by_id({interface_name}, {id})")
    q_sql = "SELECT * FROM peers WHERE interface=:interface_name AND id=:id"
    q_data = {"interface_name": interface_name, "id": id}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchone()


def get_peer_allowed_ips(interface_name: str) -> list[sqlite3.Row]:
    """
    Returns the `allowed_ips` of all peers of `interface_name`.
    """
    app.logger.debug(f"db.get_peer_allowed_ips({interface_name})")
    q_sql = "SELECT allowed_ips FROM peers WHERE interface=:interface_name"
    q_data = {"interface_name": interface_name}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchall()


def get_peer_ids(interface_name: str) -> list[sqlite3.Row]:
    """
    Returns the `id`s of all peers of `interface_name`.
    """
    app.logger.debug(f"db.get_peer_ids({interface_name})")
    q_sql = "SELECT id FROM peers WHERE interface=:interface_name"
    q_data = {"interface_name": interface_name}
    data = _cursor.execute(q_sql, q_data)
    return data.fetchall()


def remove_stale_peers(interface_name: str, peer_data: dict):
    """
    Removes from the DB entries that are present there, but not in `peer_data`
    """

    app.logger.debug(f"db.remove_stale_peers({interface_name}, peer_data)")
    db_key = set(map(lambda a: a[0], get_peer_ids(interface_name)))
    wg_key = set(map(lambda a: a["PublicKey"], peer_data["Peers"]))
    app.logger.debug(f"db_key: {db_key}")
    app.logger.debug(f"wg_key: {wg_key}")
    for id in db_key - wg_key:
        delete_peer(interface_name, id)


def delete_peer(interface_name: str, id: str):
    """
    Removes a peer of `interface_name` with the given `id`
    """
    app.logger.debug(f"db.delete_peer({interface_name}, {id})")
    q_sql = "DELETE FROM peers WHERE interface=:interface_name AND id=:id"
    q_data = {"interface_name": interface_name, "id": id}

    execute_locked(q_sql, q_data)


def insert_peer(interface_name: str, data: dict):
    """
    Inserts a peer of `interface_name` with the given `data`
    """
    app.logger.debug(f"db.insert_peer({interface_name}, {data})")
    q_data = data.copy()
    q_data.update({"interface_name": interface_name})
    q_sql = f"""
    INSERT INTO peers
        VALUES (:interface_name, :id, :private_key, :DNS, :endpoint_allowed_ips, :name, :total_receive, :total_sent, 
        :total_data, :endpoint, :status, :latest_handshake, :allowed_ips, :cumu_receive, :cumu_sent, 
        :cumu_data, :mtu, :keepalive, :remote_endpoint, :preshared_key);
    """

    execute_locked(q_sql, q_data)


def update_peer(interface_name: str, data: dict):
    """
    Updates the peer of `interface_name` with the given `data`, if the peer record exists.
    """
    app.logger.debug(f"db.interface_name({data})")
    id = data["id"]
    db_peer = get_peer_by_id(interface_name, id)
    if db_peer:
        db_peer = dict(db_peer)
        db_peer.update(data)
        _update_peer(interface_name, db_peer)


def _update_peer(interface_name: str, data: dict):
    """
    Updates the peer of `interface_name` with the given `data`.
    `data` should contain the peer's `id` (public key), plus any other field to be updated.
    """
    app.logger.debug(f"db.update_peer({interface_name}, {data})")
    q_data = data.copy()
    q_data.update({"interface_name": interface_name})
    q_sql = f"""
    UPDATE peers SET     
    private_key=:private_key, DNS=:DNS, endpoint_allowed_ips=:endpoint_allowed_ips, name=:name, 
    total_receive=:total_receive, total_sent=:total_sent,  total_data=:total_data, endpoint=:endpoint, status=:status,
    latest_handshake=:latest_handshake, allowed_ips=:allowed_ips, cumu_receive=:cumu_receive, cumu_sent=:cumu_sent, 
    cumu_data=:cumu_data, mtu=:mtu, keepalive=:keepalive, remote_endpoint=:remote_endpoint, preshared_key=:preshared_key
    WHERE id = :id AND interface = :interface_name
    """
    execute_locked(q_sql, q_data)
