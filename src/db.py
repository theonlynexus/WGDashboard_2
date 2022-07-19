from flask import g
from flask import current_app as app


def get_net_stats(config_name: str) -> list:
    data = g.cur.execute(
        f"SELECT total_sent, total_receive, cumu_sent, cumu_receive FROM {config_name}"
    )
    return data.fetchall()


def get_net_stats_and_peer_status(config_name: str, id: str) -> list:
    data = g.cur.execute(
        "SELECT total_receive, total_sent, cumu_receive, cumu_sent, status FROM %s WHERE id='%s'"
        % (config_name, id)
    )
    return data.fetchone()


def get_peers(config_name: str, search: str = None) -> list:
    """Returns the list of records which name matches the search string, or all if no search is provided"""

    app.logger.debug(f"db.get_peers({config_name}, {search})")
    sql = f"SELECT * FROM {config_name}"
    if search:
        sql += f" WHERE name LIKE '%{search}%'"
    else:
        sql = "SELECT * FROM " + config_name + " WHERE name LIKE '%" + search + "%'"
    data = g.cur.execute(sql)
    return data.fetchall()


def get_peer_by_id(config_name: str, id: str) -> list:
    """Returns the record matching the pass id or None."""

    app.logger.debug(f"db.get_peer_by_id({config_name}, {id})")
    sql = "SELECT * FROM %s WHERE id='%s'" % (config_name, id)
    data = g.cur.execute(sql)
    return data.fetchone()


def remove_stale_peers(config_name: str, peer_data: str):
    """Removes entries that which id is present in the db, but not in peer_data"""

    app.logger.debug(f"db.remove_stale_peers({config_name}, peer_data)")
    db_key = set(map(lambda a: a[0], g.cur.execute("SELECT id FROM %s" % config_name)))
    wg_key = set(map(lambda a: a["PublicKey"], peer_data["Peers"]))
    app.logger.debug(f"db_key: {db_key}")
    app.logger.debug(f"wg_key: {wg_key}")
    for id in db_key - wg_key:
        delete_peer(config_name, id)


def delete_peer(config_name: str, id: str):
    app.logger.debug(f"db.delete_peer({config_name}, {id})")
    sql = "DELETE FROM %s WHERE id = '%s'" % (config_name, id)
    g.cur.execute(sql)


def insert_peer(config_name: str, data: dict):
    app.logger.debug(f"db.insert_peer({config_name}, {data})")
    sql = f"""
    INSERT INTO {config_name} 
        VALUES (:id, :private_key, :DNS, :endpoint_allowed_ip, :name, :total_receive, :total_sent, 
        :total_data, :endpoint, :status, :latest_handshake, :allowed_ip, :cumu_receive, :cumu_sent, 
        :cumu_data, :mtu, :keepalive, :remote_endpoint, :preshared_key);
    """
    g.cur.execute(sql, data)


def update_peer(config_name: str, data: dict):
    app.logger.debug(f"db.update_peer({config_name}, {data})")
    sql = f"""
    UPDATE {config_name} SET     
    private_key=:private_key, DNS=:DNS, endpoint_allowed_ip=:endpoint_allowed_ip, name=:name, 
    total_receive=:total_receive, total_sent=:total_sent,  total_data=:total_data, endpoint=:endpoint, status=:status,
    latest_handshake=:latest_handshake, allowed_ip=:allowed_ip, cumu_receive=:cumu_receive, cumu_sent=:cumu_sent, 
    cumu_data=:cumu_data, mtu=:mtu, keepalive=:keepalive, remote_endpoint=:remote_endpoint, preshared_key=:preshared_key
    WHERE id = :id
    """
    g.cur.execute(sql, data)
