"""
< WGDashboard > - Copyright(C) 2021 Donald Zou [https://github.com/donaldzou]
Under Apache-2.0 License
"""

from selectors import EpollSelector
import sqlite3
import configparser
import hashlib
import ipaddress
import json

# Python Built-in Library
import os
import secrets
import subprocess
import time
import re
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from operator import itemgetter

# PIP installed library
import ifcfg
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    session,
    jsonify,
    g,
)
from flask_qrcode import QRcode
from icmplib import ping, traceroute

# Import other python files
from util import (
    regex_match,
    check_DNS,
    check_Allowed_IPs,
    check_remote_endpoint,
    check_IP_with_range,
    clean_IP_with_range,
    ensure_subnet,
    strip_subnet,
)


import db, wg

# Dashboard Version
DASHBOARD_VERSION = "v3.0.6"

# Dashboard Config Name
configuration_path = "/config"
WG_CONF_DIR = configuration_path
WG_SERVER_CONF_FILE = os.path.join(configuration_path, "wg0.conf")
DB_PATH = os.path.join(configuration_path, "db")
if not os.path.isdir(DB_PATH):
    os.mkdir(DB_PATH)
DASHBOARD_CONF_FILE = os.path.join(configuration_path, "wg-dashboard.ini")
SERVER_PRIVATE_KEY_FILE = os.path.join(
    configuration_path, "server", "privatekey-server"
)
SERVER_PUBLIC_KEY_FILE = os.path.join(configuration_path, "server", "publickey-server")
SERVER_CONFIG_FILE = os.path.join(configuration_path, "wg0.conf")

# Upgrade Required
UPDATE = None

# Flask App Configuration
app = Flask("WGDashboard")
app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 5206928
app.secret_key = secrets.token_urlsafe(16)
app.config["TEMPLATES_AUTO_RELOAD"] = True
app.logger.setLevel("DEBUG")

# Enable QR Code Generator
QRcode(app)

# TODO: use class and object oriented programming


def connect_db():
    """
    Connect to the database
    @return: sqlite3.Connection
    """
    con = sqlite3.connect(os.path.join(configuration_path, "db", "wgdashboard.db"))
    con.row_factory = sqlite3.Row
    return con


def read_dashboard_conf():
    """
    Get dashboard configuration
    @return: configparser.ConfigParser
    """
    r_config = configparser.ConfigParser(strict=False)
    r_config.read(DASHBOARD_CONF_FILE)
    return r_config


def write_dashboard_conf(config):
    """
    Write to configuration
    @param config: Input configuration
    """
    with open(DASHBOARD_CONF_FILE, "w", encoding="utf-8") as conf_object:
        config.write(conf_object)


def wg_peer_data_to_db(config_name):
    """
    Look for new peers from WireGuard
    @param config_name: Configuration name
    @return: None
    """
    interface_and_peer_data = wg.read_interface_config_file(config_name, WG_CONF_DIR)
    config = read_dashboard_conf()
    failed_index = []
    for i in range(len(interface_and_peer_data["Peers"])):
        wg_peer = interface_and_peer_data["Peers"][i]
        if "PublicKey" in wg_peer.keys():
            data = db.get_peer_by_id(
                config_name, interface_and_peer_data["Peers"][i]["PublicKey"]
            )
            if not data:
                new_data = {
                    "id": interface_and_peer_data["Peers"][i]["PublicKey"],
                    "private_key": "",
                    "DNS": config.get("Peers", "peer_global_DNS"),
                    "endpoint_allowed_ip": config.get(
                        "Peers", "peer_endpoint_allowed_ip"
                    ),
                    "name": "",
                    "total_receive": 0,
                    "total_sent": 0,
                    "total_data": 0,
                    "endpoint": "N/A",
                    "status": "stopped",
                    "latest_handshake": "N/A",
                    "allowed_ip": "N/A",
                    "cumu_receive": 0,
                    "cumu_sent": 0,
                    "cumu_data": 0,
                    "traffic": [],
                    "mtu": config.get("Peers", "peer_mtu"),
                    "keepalive": config.get("Peers", "peer_keep_alive"),
                    "remote_endpoint": config.get("Peers", "remote_endpoint"),
                    "preshared_key": "",
                }
                if "PresharedKey" in interface_and_peer_data["Peers"][i].keys():
                    new_data["preshared_key"] = interface_and_peer_data["Peers"][i][
                        "PresharedKey"
                    ]
                db.insert_peer(config_name, new_data)
        else:
            print("Trying to parse a peer doesn't have public key...")
            failed_index.append(i)
    for i in failed_index:
        interface_and_peer_data["Peers"].pop(i)

    db.remove_stale_peers(config_name, interface_and_peer_data)

    handshakes = wg.get_interface_peers_latest_handshakes(config_name)
    transfers = wg.get_interface_peers_net_stats(config_name)
    endpoints = wg.get_interface_peers_endpoints(config_name)
    allowed_ips = wg.get_interface_peers_allowed_ips(
        interface_and_peer_data, config_name
    )
    keys = set()
    for x in [handshakes, transfers, endpoints, allowed_ips]:
        app.logger.debug(x)
        keys.update(x.keys())
    for id in keys:
        data = {"id": id}
        for x in [handshakes, transfers, endpoints, allowed_ips]:
            try:
                data.update(x[id])
            except KeyError:
                pass
        db.update_peer(config_name, data)


def update_db_and_get_peers(config_name, search, sort_t):
    """
    Get all peers.
    @param config_name: Name of WG interface
    @type config_name: str
    @param search: Search string
    @type search: str
    @param sort_t: Sorting tag
    @type sort_t: str
    @return: list
    """
    tic = time.perf_counter()
    wg_peer_data_to_db(config_name)

    result = list(map(lambda x: dict(x), db.get_peers(config_name, search)))

    if sort_t == "allowed_ip":
        result = sorted(
            result,
            key=lambda d: ipaddress.ip_network(
                "0.0.0.0/0"
                if d[sort_t].split(",")[0] == "(None)"
                else d[sort_t].split(",")[0]
            ),
        )
    else:
        result = sorted(result, key=lambda d: d[sort_t])
    toc = time.perf_counter()
    app.logger.debug(f"Finish fetching peers in {toc - tic:0.4f} seconds")
    return result


def get_conf_list():
    """Get all wireguard interfaces with status.

    @return: Return a list of dicts with interfaces and its statuses
    @rtype: list
    """

    conf = []
    if_name = WG_SERVER_CONF_FILE.split("/")[-1]
    if regex_match("^(.{1,}).(conf)$", if_name):
        if_name = if_name.split(".")[0]
        db.create_table_if_missing(if_name)
        temp = {
            "conf": if_name,
            "status": wg.get_interface_status(if_name),
            "public_key": wg.get_interface_public_key(if_name, WG_CONF_DIR),
        }
        if temp["status"] == "running":
            temp["checked"] = "checked"
        else:
            temp["checked"] = ""
        conf.append(temp)
    if len(conf) > 0:
        conf = sorted(conf, key=itemgetter("conf"))
    return conf


def f_check_key_match(private_key, public_key, config_name):
    """
    Check if private key and public key match
    @param private_key: Private key
    @type private_key: str
    @param public_key: Public key
    @type public_key: str
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return dictionary with status
    @rtype: dict
    """

    result = wg.gen_public_key(private_key)
    if result["status"] == "failed":
        return result
    else:
        sql = "SELECT * FROM " + config_name + " WHERE id = ?"
        match = g.cur.execute(sql, (result["data"],)).fetchall()
        if len(match) != 1 or result["data"] != public_key:
            return {
                "status": "failed",
                "msg": "Please check your private key, it does not match with the public key.",
            }
        else:
            return {"status": "success"}


def check_repeat_allowed_ip(public_key, ip, config_name):
    """
    Check if there are repeated IPs
    @param public_key: Public key of the peer
    @param ip: IP of the peer
    @param config_name: configuration name
    @return: a JSON object
    """
    peer = g.cur.execute(
        "SELECT COUNT(*) FROM " + config_name + " WHERE id = ?", (public_key,)
    ).fetchone()
    if peer[0] != 1:
        return {"status": "failed", "msg": "Peer does not exist"}
    else:
        existed_ip = g.cur.execute(
            "SELECT COUNT(*) FROM "
            + config_name
            + " WHERE id != ? AND allowed_ip LIKE '"
            + ip
            + "/%'",
            (public_key,),
        ).fetchone()
        if existed_ip[0] != 0:
            return {
                "status": "failed",
                "msg": "Allowed IP already taken by another peer.",
            }
        else:
            return {"status": "success"}


def f_available_ips(config_name):
    """
    Get a list of available IPs
    @param config_name: Configuration Name
    @return: list
    """
    config_interface = wg.read_interface_section_from_config_file(
        config_name, WG_CONF_DIR
    )
    if "Address" in config_interface:
        existing = set()
        conf_address = config_interface["Address"]
        address = list(map(lambda x: x.strip(), conf_address.split(",")))
        for i in address:
            add = strip_subnet(i)
            existing.add(ipaddress.ip_address(add))
        peers = g.cur.execute("SELECT allowed_ip FROM " + config_name).fetchall()
        for i in peers:
            add = i[0].split(",")
            for k in add:
                a = strip_subnet(k)
                existing.add(ipaddress.ip_address(a.strip()))
        available = set(ipaddress.ip_network(ensure_subnet(address[0]), False).hosts())
        available -= existing
        available = list(map(lambda x: str(x), sorted(available)))
        return available
    else:
        return []


"""
Flask Functions
"""


@app.teardown_request
def close_DB(exception):
    """
    Commit to the database for every request
    @param exception: Exception
    @return: None
    """
    if hasattr(g, "db"):
        g.db.commit()
        g.db.close()


@app.before_request
def auth_req():
    """
    Action before every request
    @return: Redirect
    """
    if getattr(g, "db", None) is None:
        g.db = connect_db()
        g.cur = g.db.cursor()
    init_dashboard()
    conf = read_dashboard_conf()
    req = conf.get("Server", "auth_req")
    session["update"] = UPDATE
    session["dashboard_version"] = DASHBOARD_VERSION
    if req == "true":
        if (
            "/static/" not in request.path
            and request.endpoint != "signin"
            and request.endpoint != "signout"
            and request.endpoint != "auth"
            and "username" not in session
        ):
            app.logger.info(
                "User not signed in - Attempted access: " + str(request.endpoint)
            )
            if request.endpoint != "index":
                session["message"] = "You need to sign in first!"
            else:
                session["message"] = ""
            conf.clear()
            redirectURL = str(request.url)
            redirectURL = redirectURL.replace("http://", "")
            redirectURL = redirectURL.replace("https://", "")
            return redirect("/signin?redirect=" + redirectURL)
    else:
        if request.endpoint in [
            "signin",
            "signout",
            "auth",
            "settings",
            "update_acct",
            "update_pwd",
            "update_app_ip_port",
            "update_wg_conf_path",
        ]:
            conf.clear()
            return redirect(url_for("index"))
    conf.clear()
    return None


"""
Sign In / Sign Out
"""


@app.route("/signin", methods=["GET"])
def signin():
    """
    Sign in request
    @return: template
    """

    message = ""
    if "message" in session:
        message = session["message"]
        session.pop("message")
    return render_template("signin.html", message=message, version=DASHBOARD_VERSION)


# Sign Out
@app.route("/signout", methods=["GET"])
def signout():
    """
    Sign out request
    @return: redirect back to sign in
    """
    if "username" in session:
        session.pop("username")
    return redirect(url_for("signin"))


@app.route("/auth", methods=["POST"])
def auth():
    """
    Authentication request
    @return: json object indicating verifying
    """
    data = request.get_json()
    config = read_dashboard_conf()
    password = hashlib.sha256(data["password"].encode())
    if (
        password.hexdigest() == config["Account"]["password"]
        and data["username"] == config["Account"]["username"]
    ):
        session["username"] = data["username"]
        config.clear()
        return jsonify({"status": True, "msg": ""})
    config.clear()
    return jsonify({"status": False, "msg": "Username or Password is incorrect."})


"""
Index Page
"""


@app.route("/", methods=["GET"])
def index():
    """
    Index page related
    @return: Template
    """
    msg = ""
    if "switch_msg" in session:
        msg = session["switch_msg"]
        session.pop("switch_msg")

    return render_template("index.html", conf=get_conf_list(), msg=msg)


# Setting Page
@app.route("/settings", methods=["GET"])
def settings():
    """
    Settings page related
    @return: Template
    """
    message = ""
    status = ""
    config = read_dashboard_conf()
    if "message" in session and "message_status" in session:
        message = session["message"]
        status = session["message_status"]
        session.pop("message")
        session.pop("message_status")
    required_auth = config.get("Server", "auth_req")
    return render_template(
        "settings.html",
        conf=get_conf_list(),
        message=message,
        status=status,
        required_auth=required_auth,
        wg_conf_path=config.get("Server", "wg_conf_path"),
        peer_global_DNS=config.get("Peers", "peer_global_DNS"),
        peer_endpoint_allowed_ip=config.get("Peers", "peer_endpoint_allowed_ip"),
        peer_mtu=config.get("Peers", "peer_mtu"),
        peer_keepalive=config.get("Peers", "peer_keep_alive"),
        peer_remote_endpoint=config.get("Peers", "remote_endpoint"),
    )


@app.route("/update_acct", methods=["POST"])
def update_acct():
    """
    Change dashboard username
    @return: Redirect
    """

    if len(request.form["username"]) == 0:
        session["message"] = "Username cannot be empty."
        session["message_status"] = "danger"
        return redirect(url_for("settings"))
    config = read_dashboard_conf()
    config.set("Account", "username", request.form["username"])
    try:
        write_dashboard_conf(config)
        config.clear()
        session["message"] = "Username updated successfully!"
        session["message_status"] = "success"
        session["username"] = request.form["username"]
        return redirect(url_for("settings"))
    except Exception:
        session["message"] = "Username update failed."
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))


# Update peer default setting
@app.route("/update_peer_default_config", methods=["POST"])
def update_peer_default_config():
    """
    Update new peers default setting
    @return: None
    """

    config = read_dashboard_conf()
    if (
        len(request.form["peer_endpoint_allowed_ip"]) == 0
        or len(request.form["peer_global_DNS"]) == 0
        or len(request.form["peer_remote_endpoint"]) == 0
    ):
        session["message"] = "Please fill in all required boxes."
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    # Check DNS Format
    dns_addresses = request.form["peer_global_DNS"]
    if not check_DNS(dns_addresses):
        session["message"] = "Peer DNS Format Incorrect."
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    dns_addresses = dns_addresses.replace(" ", "").split(",")
    dns_addresses = ",".join(dns_addresses)
    # Check Endpoint Allowed IPs
    ip = request.form["peer_endpoint_allowed_ip"]
    if not check_Allowed_IPs(ip):
        session["message"] = (
            "Peer Endpoint Allowed IPs Format Incorrect. "
            "Example: 192.168.1.1/32 or 192.168.1.1/32,192.168.1.2/32"
        )
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    # Check MTU Format
    if not len(request.form["peer_mtu"]) > 0 or not request.form["peer_mtu"].isdigit():
        session["message"] = "MTU format is incorrect."
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    # Check keepalive Format
    if (
        not len(request.form["peer_keep_alive"]) > 0
        or not request.form["peer_keep_alive"].isdigit()
    ):
        session["message"] = "Persistent keepalive format is incorrect."
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    # Check peer remote endpoint
    if not check_remote_endpoint(request.form["peer_remote_endpoint"]):
        session["message"] = (
            "Peer Remote Endpoint format is incorrect. It can only be a valid "
            "IP address or valid domain (without http:// or https://). "
        )
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))
    config.set("Peers", "remote_endpoint", request.form["peer_remote_endpoint"])
    config.set("Peers", "peer_keep_alive", request.form["peer_keep_alive"])
    config.set("Peers", "peer_mtu", request.form["peer_mtu"])
    config.set("Peers", "peer_endpoint_allowed_ip", ",".join(clean_IP_with_range(ip)))
    config.set("Peers", "peer_global_DNS", dns_addresses)
    try:
        write_dashboard_conf(config)
        session["message"] = "Peer Default Settings update successfully!"
        session["message_status"] = "success"
        config.clear()
        return redirect(url_for("settings"))
    except Exception:
        session["message"] = "Peer Default Settings update failed."
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))


# Update dashboard password
@app.route("/update_pwd", methods=["POST"])
def update_pwd():
    """
    Update dashboard password
    @return: Redirect
    """

    config = read_dashboard_conf()
    if hashlib.sha256(request.form["currentpass"].encode()).hexdigest() == config.get(
        "Account", "password"
    ):
        if (
            hashlib.sha256(request.form["newpass"].encode()).hexdigest()
            == hashlib.sha256(request.form["repnewpass"].encode()).hexdigest()
        ):
            config.set(
                "Account",
                "password",
                hashlib.sha256(request.form["repnewpass"].encode()).hexdigest(),
            )
            try:
                write_dashboard_conf(config)
                session["message"] = "Password updated successfully!"
                session["message_status"] = "success"
                config.clear()
                return redirect(url_for("settings"))
            except Exception:
                session["message"] = "Password update failed"
                session["message_status"] = "danger"
                config.clear()
                return redirect(url_for("settings"))
        else:
            session["message"] = "Your New Password does not match."
            session["message_status"] = "danger"
            config.clear()
            return redirect(url_for("settings"))
    else:
        session["message"] = "Your Password does not match."
        session["message_status"] = "danger"
        config.clear()
        return redirect(url_for("settings"))


@app.route("/update_app_ip_port", methods=["POST"])
def update_app_ip_port():
    """
    Update dashboard ip and port
    @return: None
    """

    config = read_dashboard_conf()
    config.set("Server", "app_ip", request.form["app_ip"])
    config.set("Server", "app_port", request.form["app_port"])
    write_dashboard_conf(config)
    config.clear()
    subprocess.Popen("bash wgd.sh restart", shell=True)
    return ""


# Update WireGuard configuration file path
@app.route("/update_wg_conf_path", methods=["POST"])
def update_wg_conf_path():
    """
    Update configuration path
    @return: None
    """

    config = read_dashboard_conf()
    config.set("Server", "wg_conf_path", request.form["wg_conf_path"])
    write_dashboard_conf(config)
    config.clear()
    session["message"] = "WireGuard Configuration Path updated successfully!"
    session["message_status"] = "success"
    subprocess.Popen("bash wgd.sh restart", shell=True)


@app.route("/update_dashboard_sort", methods=["POST"])
def update_dashbaord_sort():
    """
    Update configuration sorting
    @return: Boolean
    """

    config = read_dashboard_conf()
    data = request.get_json()
    sort_tag = ["name", "status", "allowed_ip"]
    if data["sort"] in sort_tag:
        config.set("Server", "dashboard_sort", data["sort"])
    else:
        config.set("Server", "dashboard_sort", "status")
    write_dashboard_conf(config)
    config.clear()
    return "true"


# Update configuration refresh interval
@app.route("/update_dashboard_refresh_interval", methods=["POST"])
def update_dashboard_refresh_interval():
    """
    Change the refresh time.
    @return: Return text with result
    @rtype: str
    """

    preset_interval = ["5000", "10000", "30000", "60000"]
    if request.form["interval"] in preset_interval:
        config = read_dashboard_conf()
        config.set(
            "Server", "dashboard_refresh_interval", str(request.form["interval"])
        )
        write_dashboard_conf(config)
        config.clear()
        return "true"
    else:
        return "false"


# Configuration Page
@app.route("/configuration/<config_name>", methods=["GET"])
def configuration(config_name):
    """
    Show wireguard interface view.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Template
    """

    config = read_dashboard_conf()
    conf_data = {
        "name": config_name,
        "status": wg.get_interface_status(config_name),
        "checked": "",
    }
    if conf_data["status"] == "stopped":
        conf_data["checked"] = "nope"
    else:
        conf_data["checked"] = "checked"
    config_list = get_conf_list()
    if config_name not in [conf["conf"] for conf in config_list]:
        return render_template("index.html", conf=get_conf_list())

    refresh_interval = int(config.get("Server", "dashboard_refresh_interval"))
    dns_address = config.get("Peers", "peer_global_DNS")
    allowed_ip = config.get("Peers", "peer_endpoint_allowed_ip")
    peer_mtu = config.get("Peers", "peer_MTU")
    peer_keep_alive = config.get("Peers", "peer_keep_alive")
    config.clear()
    return render_template(
        "configuration.html",
        conf=get_conf_list(),
        conf_data=conf_data,
        dashboard_refresh_interval=refresh_interval,
        DNS=dns_address,
        endpoint_allowed_ip=allowed_ip,
        title=config_name,
        mtu=peer_mtu,
        keep_alive=peer_keep_alive,
    )


# Get configuration details
@app.route("/get_config/<config_name>", methods=["GET"])
def get_conf(config_name):
    """
    Get configuration setting of wireguard interface.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: TODO
    """

    config_interface = wg.read_interface_section_from_config_file(
        config_name, WG_CONF_DIR
    )
    search = request.args.get("search")
    if len(search) == 0:
        search = ""
    search = urllib.parse.unquote(search)
    config = read_dashboard_conf()
    sort = config.get("Server", "dashboard_sort")
    peer_display_mode = config.get("Peers", "peer_display_mode")
    wg_ip = config.get("Peers", "remote_endpoint")
    if "Address" not in config_interface:
        conf_address = "N/A"
    else:
        conf_address = config_interface["Address"]
    conf_data = {
        "peer_data": update_db_and_get_peers(config_name, search, sort),
        "name": config_name,
        "status": wg.get_interface_status(config_name),
        "total_data_usage": wg.get_interface_total_net_stats(config_name),
        "public_key": wg.get_interface_public_key(config_name, WG_CONF_DIR),
        "listen_port": wg.get_interface_listen_port(config_name, WG_CONF_DIR),
        "running_peer": wg.get_interface_running_peer_count(config_name),
        "conf_address": conf_address,
        "wg_ip": wg_ip,
        "sort_tag": sort,
        "dashboard_refresh_interval": int(
            config.get("Server", "dashboard_refresh_interval")
        ),
        "peer_display_mode": peer_display_mode,
    }
    if conf_data["status"] == "stopped":
        conf_data["checked"] = "nope"
    else:
        conf_data["checked"] = "checked"
    config.clear()
    return jsonify(conf_data)


# Turn on / off a configuration
@app.route("/switch/<config_name>", methods=["GET"])
def switch(config_name):
    """
    On/off the wireguard interface.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: redirects
    """

    status = wg.get_interface_status(config_name)
    config_file = os.path.join(WG_CONF_DIR, f"{config_name}.conf")
    try:
        wg.switch_interface(config_name, WG_CONF_DIR)
    except subprocess.CalledProcessError as exc:
        session["switch_msg"] = exc.output.strip().decode("utf-8")
        return redirect("/")
    return redirect(request.referrer)


@app.route("/add_peer_bulk/<config_name>", methods=["POST"])
def add_peer_bulk(config_name):
    """
    Add peers by bulk
    @param config_name: Configuration Name
    @return: String
    """
    data = request.get_json()
    keys = data["keys"]
    endpoint_allowed_ip = data["endpoint_allowed_ip"]
    dns_addresses = data["DNS"]
    enable_preshared_key = data["enable_preshared_key"]
    amount = data["amount"]
    config_interface = wg.read_interface_section_from_config_file(
        config_name, WG_CONF_DIR
    )
    if "Address" not in config_interface:
        return "Configuration must have an IP address."
    if not amount.isdigit() or int(amount) < 1:
        return "Amount must be integer larger than 0"
    amount = int(amount)
    if not check_DNS(dns_addresses):
        return "DNS formate is incorrect. Example: 1.1.1.1"
    if not check_Allowed_IPs(endpoint_allowed_ip):
        return "Endpoint Allowed IPs format is incorrect."
    if len(data["MTU"]) == 0 or not data["MTU"].isdigit():
        return "MTU format is not correct."
    if len(data["keep_alive"]) == 0 or not data["keep_alive"].isdigit():
        return "Persistent Keepalive format is not correct."
    ips = f_available_ips(config_name)
    if amount > len(ips):
        return f"Cannot create more than {len(ips)} peers."
    wg_command = ["wg", "set", config_name]
    sql_command = []
    for i in range(amount):
        keys[i][
            "name"
        ] = f"{config_name}_{datetime.now().strftime('%m%d%Y%H%M%S')}_Peer_#_{(i + 1)}"
        wg_command.append("peer")
        wg_command.append(keys[i]["publicKey"])
        keys[i]["allowed_ips"] = ips.pop(0)
        if enable_preshared_key:
            keys[i]["psk_file"] = f"{keys[i]['name']}.txt"
            f = open(keys[i]["psk_file"], "w+")
            f.write(keys[i]["presharedKey"])
            f.close()
            wg_command.append("preshared-key")
            wg_command.append(keys[i]["psk_file"])
        else:
            keys[i]["psk_file"] = ""
        wg_command.append("allowed-ips")
        wg_command.append(keys[i]["allowed_ips"])
        update = [
            "UPDATE ",
            config_name,
            " SET name = '",
            keys[i]["name"],
            "', private_key = '",
            keys[i]["privateKey"],
            "', DNS = '",
            dns_addresses,
            "', endpoint_allowed_ip = '",
            endpoint_allowed_ip,
            "' WHERE id = '",
            keys[i]["publicKey"],
            "'",
        ]
        sql_command.append(update)
    try:
        status = subprocess.check_output(
            " ".join(wg_command), shell=True, stderr=subprocess.STDOUT
        )
        wg.quick_save_interface_config(config_name, WG_CONF_DIR)
        wg_peer_data_to_db(config_name)
        if enable_preshared_key:
            for i in keys:
                os.remove(i["psk_file"])
        for i in range(len(sql_command)):
            sql_command[i] = "".join(sql_command[i])
        g.cur.executescript("; ".join(sql_command))
        return "true"
    except subprocess.CalledProcessError as exc:
        return exc.output.strip()


@app.route("/add_peer/<config_name>", methods=["POST"])
def add_peer(config_name):
    """
    Add Peers
    @param config_name: configuration name
    @return: string
    """
    data = request.get_json()
    public_key = data["public_key"]
    allowed_ips = data["allowed_ips"]
    endpoint_allowed_ip = data["endpoint_allowed_ip"]
    dns_addresses = data["DNS"]
    enable_preshared_key = data["enable_preshared_key"]
    preshared_key = data["preshared_key"]
    keys = wg.get_interface_peer_public_keys(config_name)
    if (
        len(public_key) == 0
        or len(dns_addresses) == 0
        or len(allowed_ips) == 0
        or len(endpoint_allowed_ip) == 0
    ):
        return "Please fill in all required box."
    if not isinstance(keys, list):
        return config_name + " is not running."
    if public_key in keys:
        return "Public key already exist."
    check_dup_ip = g.cur.execute(
        "SELECT COUNT(*) FROM "
        + config_name
        + " WHERE allowed_ip LIKE '"
        + allowed_ips
        + "/%'",
    ).fetchone()
    if check_dup_ip[0] != 0:
        return "Allowed IP already taken by another peer."
    if not check_DNS(dns_addresses):
        return "DNS formate is incorrect. Example: 1.1.1.1"
    if not check_Allowed_IPs(endpoint_allowed_ip):
        return "Endpoint Allowed IPs format is incorrect."
    if len(data["MTU"]) == 0 or not data["MTU"].isdigit():
        return "MTU format is not correct."
    if len(data["keep_alive"]) == 0 or not data["keep_alive"].isdigit():
        return "Persistent Keepalive format is not correct."
    try:
        if enable_preshared_key:
            now = str(datetime.now().strftime("%m%d%Y%H%M%S"))
            f_name = now + "_tmp_psk.txt"
            f = open(f_name, "w+")
            f.write(preshared_key)
            f.close()
            status = subprocess.check_output(
                f"wg set {config_name} peer {public_key} allowed-ips {allowed_ips} preshared-key {f_name}",
                shell=True,
                stderr=subprocess.STDOUT,
            )
            os.remove(f_name)
        elif not enable_preshared_key:
            status = subprocess.check_output(
                f"wg set {config_name} peer {public_key} allowed-ips {allowed_ips}",
                shell=True,
                stderr=subprocess.STDOUT,
            )

        wg.quick_save_interface_config(config_name, WG_CONF_DIR)
        wg_peer_data_to_db(config_name)
        peer = db.get_peer_by_id(config_name, public_key)
        if peer:
            peer = dict(peer)
            peer.update(
                {
                    "id": public_key,
                    "name": data["name"],
                    "private_key": data["private_key"],
                    "DNS": data["DNS"],
                    "endpoint_allowed_ip": endpoint_allowed_ip,
                }
            )
            db.update_peer(config_name, peer)
        return "true"
    except subprocess.CalledProcessError as exc:
        return exc.output.strip()


@app.route("/remove_peer/<config_name>", methods=["POST"])
def remove_peer(config_name):
    """
    Remove peer.
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return result of action or recommendations
    @rtype: str
    """

    if wg.get_interface_status(config_name) == "stopped":
        return "Your need to turn on " + config_name + " first."
    data = request.get_json()
    delete_keys = data["peer_ids"]
    keys = wg.get_interface_peer_public_keys(config_name)
    if not isinstance(keys, list):
        return config_name + " is not running."
    else:
        sql_command = []
        wg_command = ["wg", "set", config_name]
        for delete_key in delete_keys:
            if delete_key not in keys:
                return "This key does not exist"
            db.delete_peer(config_name, delete_key)
            wg_command.append("peer")
            wg_command.append(delete_key)
            wg_command.append("remove")
        try:
            remove_wg = subprocess.check_output(
                " ".join(wg_command), shell=True, stderr=subprocess.STDOUT
            )
            wg.quick_save_interface_config(config_name, WG_CONF_DIR)
            g.cur.executescript(" ".join(sql_command))
            g.db.commit()
        except subprocess.CalledProcessError as exc:
            return exc.output.strip()
        return "true"


@app.route("/save_peer_setting/<config_name>", methods=["POST"])
def save_peer_setting(config_name):
    """
    Save peer configuration.

    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return status of action and text with recommendations
    """

    data = request.get_json()
    id = data["id"]
    name = data["name"]
    private_key = data["private_key"]
    dns_addresses = data["DNS"]
    allowed_ip = data["allowed_ip"]
    endpoint_allowed_ip = data["endpoint_allowed_ip"]
    preshared_key = data["preshared_key"]
    check_peer_exist = g.cur.execute(
        "SELECT COUNT(*) FROM " + config_name + " WHERE id = ?", (id,)
    ).fetchone()
    if check_peer_exist[0] == 1:
        check_ip = check_repeat_allowed_ip(id, allowed_ip, config_name)
        if not check_IP_with_range(endpoint_allowed_ip):
            return jsonify(
                {"status": "failed", "msg": "Endpoint Allowed IPs format is incorrect."}
            )
        if not check_DNS(dns_addresses):
            return jsonify({"status": "failed", "msg": "DNS format is incorrect."})
        if len(data["MTU"]) == 0 or not data["MTU"].isdigit():
            return jsonify({"status": "failed", "msg": "MTU format is not correct."})
        if len(data["keep_alive"]) == 0 or not data["keep_alive"].isdigit():
            return jsonify(
                {
                    "status": "failed",
                    "msg": "Persistent Keepalive format is not correct.",
                }
            )
        if private_key != "":
            check_key = f_check_key_match(private_key, id, config_name)
            if check_key["status"] == "failed":
                return jsonify(check_key)
        if check_ip["status"] == "failed":
            return jsonify(check_ip)
        try:
            tmp_psk = open("tmp_edit_psk.txt", "w+")
            tmp_psk.write(preshared_key)
            tmp_psk.close()
            change_psk = subprocess.check_output(
                f"wg set {config_name} peer {id} preshared-key tmp_edit_psk.txt",
                shell=True,
                stderr=subprocess.STDOUT,
            )
            if change_psk.decode("UTF-8") != "":
                return jsonify({"status": "failed", "msg": change_psk.decode("UTF-8")})
            if allowed_ip == "":
                allowed_ip = '""'
            allowed_ip = allowed_ip.replace(" ", "")
            change_ip = subprocess.check_output(
                f"wg set {config_name} peer {id} allowed-ips {allowed_ip}",
                shell=True,
                stderr=subprocess.STDOUT,
            )
            wg.quick_save_interface_config(config_name, WG_CONF_DIR)
            if change_ip.decode("UTF-8") != "":
                return jsonify({"status": "failed", "msg": change_ip.decode("UTF-8")})

            db.update_peer(
                config_name,
                {
                    "name": name,
                    "private_key": private_key,
                    "DNS": dns_addresses,
                    "endpoint_allowed_ip": endpoint_allowed_ip,
                    "mtu": data["MTU"],
                    "keepalive": data["keep_alive"],
                    "preshared_key": preshared_key,
                    "id": id,
                },
            )
            return jsonify({"status": "success", "msg": ""})
        except subprocess.CalledProcessError as exc:
            return jsonify(
                {"status": "failed", "msg": str(exc.output.decode("UTF-8").strip())}
            )
    else:
        return jsonify({"status": "failed", "msg": "This peer does not exist."})


# Get peer settings
@app.route("/get_peer_data/<config_name>", methods=["POST"])
def get_peer_name(config_name):
    """
    Get peer settings.

    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return settings of peer
    """

    data = request.get_json()
    peer_id = data["id"]
    result = g.cur.execute(
        "SELECT name, allowed_ip, DNS, private_key, endpoint_allowed_ip, mtu, keepalive, preshared_key FROM "
        + config_name
        + " WHERE id = ?",
        (peer_id,),
    ).fetchall()
    data = {
        "name": result[0][0],
        "allowed_ip": result[0][1],
        "DNS": result[0][2],
        "private_key": result[0][3],
        "endpoint_allowed_ip": result[0][4],
        "mtu": result[0][5],
        "keep_alive": result[0][6],
        "preshared_key": result[0][7],
    }
    return jsonify(data)


# Return available IPs
@app.route("/available_ips/<config_name>", methods=["GET"])
def available_ips(config_name):
    return jsonify(f_available_ips(config_name))


# Check if both key match
@app.route("/check_key_match/<config_name>", methods=["POST"])
def check_key_match(config_name):
    """
    Check key matches
    @param config_name: Name of WG interface
    @type config_name: str
    @return: Return dictionary with status
    """

    data = request.get_json()
    private_key = data["private_key"]
    public_key = data["public_key"]
    return jsonify(f_check_key_match(private_key, public_key, config_name))


@app.route("/qrcode/<config_name>", methods=["GET"])
def generate_qrcode(config_name):
    """
    Generate QRCode
    @param config_name: Configuration Name
    @return: Template containing QRcode img
    """
    peer_id = request.args.get("id")
    get_peer = g.cur.execute(
        "SELECT private_key, allowed_ip, DNS, mtu, endpoint_allowed_ip, keepalive, preshared_key FROM "
        + config_name
        + " WHERE id = ?",
        (peer_id,),
    ).fetchall()
    config = read_dashboard_conf()
    if len(get_peer) == 1:
        peer = get_peer[0]
        if peer[0] != "":
            public_key = wg.get_interface_public_key(config_name, WG_CONF_DIR)
            listen_port = wg.get_interface_listen_port(config_name, WG_CONF_DIR)
            endpoint = config.get("Peers", "remote_endpoint") + ":" + listen_port
            private_key = peer[0]
            allowed_ip = peer[1]
            dns_addresses = peer[2]
            mtu_value = peer[3]
            endpoint_allowed_ip = peer[4]
            keepalive = peer[5]
            preshared_key = peer[6]

            result = (
                "[Interface]\nPrivateKey = "
                + private_key
                + "\nAddress = "
                + allowed_ip
                + "\nMTU = "
                + str(mtu_value)
                + "\nDNS = "
                + dns_addresses
                + "\n\n[Peer]\nPublicKey = "
                + public_key
                + "\nAllowedIPs = "
                + endpoint_allowed_ip
                + "\nPersistentKeepalive = "
                + str(keepalive)
                + "\nEndpoint = "
                + endpoint
            )
            if preshared_key != "":
                result += "\nPresharedKey = " + preshared_key
            return render_template("qrcode.html", i=result)
    else:
        return redirect("/configuration/" + config_name)


@app.route("/download_all/<config_name>", methods=["GET"])
def download_all(config_name):
    """
    Download all configuration
    @param config_name: Configuration Name
    @return: JSON Object
    """
    get_peer = g.cur.execute(
        "SELECT private_key, allowed_ip, DNS, mtu, endpoint_allowed_ip, keepalive, preshared_key, name FROM "
        + config_name
        + " WHERE private_key != ''"
    ).fetchall()
    config = read_dashboard_conf()
    data = []
    public_key = wg.get_interface_public_key(config_name, WG_CONF_DIR)
    listen_port = wg.get_interface_listen_port(config_name, WG_CONF_DIR)
    endpoint = config.get("Peers", "remote_endpoint") + ":" + listen_port
    for peer in get_peer:
        private_key = peer[0]
        allowed_ip = peer[1]
        dns_addresses = peer[2]
        mtu_value = peer[3]
        endpoint_allowed_ip = peer[4]
        keepalive = peer[5]
        preshared_key = peer[6]
        filename = peer[7]
        if len(filename) == 0:
            filename = "Untitled_Peer"
        else:
            filename = peer[7]
            # Clean filename
            illegal_filename = [
                ".",
                ",",
                "/",
                "?",
                "<",
                ">",
                "\\",
                ":",
                "*",
                "|" '"',
                "com1",
                "com2",
                "com3",
                "com4",
                "com5",
                "com6",
                "com7",
                "com8",
                "com9",
                "lpt1",
                "lpt2",
                "lpt3",
                "lpt4",
                "lpt5",
                "lpt6",
                "lpt7",
                "lpt8",
                "lpt9",
                "con",
                "nul",
                "prn",
            ]
            for i in illegal_filename:
                filename = filename.replace(i, "")
            if len(filename) == 0:
                filename = "Untitled_Peer"
            filename = "".join(filename.split(" "))
        filename = filename + "_" + config_name
        psk = ""
        if preshared_key != "":
            psk = "\nPresharedKey = " + preshared_key

        return_data = (
            "[Interface]\nPrivateKey = "
            + private_key
            + "\nAddress = "
            + allowed_ip
            + "\nDNS = "
            + dns_addresses
            + "\nMTU = "
            + str(mtu_value)
            + "\n\n[Peer]\nPublicKey = "
            + public_key
            + "\nAllowedIPs = "
            + endpoint_allowed_ip
            + "\nEndpoint = "
            + endpoint
            + "\nPersistentKeepalive = "
            + str(keepalive)
            + psk
        )
        data.append({"filename": f"{filename}.conf", "content": return_data})
    return jsonify({"status": True, "peers": data, "filename": f"{config_name}.zip"})


# Download configuration file
@app.route("/download/<config_name>", methods=["GET"])
def download(config_name):
    """
    Download one configuration
    @param config_name: Configuration name
    @return: JSON object
    """
    peer_id = request.args.get("id")
    get_peer = g.cur.execute(
        "SELECT private_key, allowed_ip, DNS, mtu, endpoint_allowed_ip, keepalive, preshared_key, name FROM "
        + config_name
        + " WHERE id = ?",
        (peer_id,),
    ).fetchall()
    config = read_dashboard_conf()
    if len(get_peer) == 1:
        peer = get_peer[0]
        if peer[0] != "":
            public_key = wg.get_interface_public_key(config_name, WG_CONF_DIR)
            listen_port = wg.get_interface_listen_port(config_name, WG_CONF_DIR)
            endpoint = config.get("Peers", "remote_endpoint") + ":" + listen_port
            private_key = peer[0]
            allowed_ip = peer[1]
            dns_addresses = peer[2]
            mtu_value = peer[3]
            endpoint_allowed_ip = peer[4]
            keepalive = peer[5]
            preshared_key = peer[6]
            filename = peer[7]
            if len(filename) == 0:
                filename = "Untitled_Peer"
            else:
                filename = peer[7]
                # Clean filename
                illegal_filename = [
                    ".",
                    ",",
                    "/",
                    "?",
                    "<",
                    ">",
                    "\\",
                    ":",
                    "*",
                    "|" '"',
                    "com1",
                    "com2",
                    "com3",
                    "com4",
                    "com5",
                    "com6",
                    "com7",
                    "com8",
                    "com9",
                    "lpt1",
                    "lpt2",
                    "lpt3",
                    "lpt4",
                    "lpt5",
                    "lpt6",
                    "lpt7",
                    "lpt8",
                    "lpt9",
                    "con",
                    "nul",
                    "prn",
                ]
                for i in illegal_filename:
                    filename = filename.replace(i, "")
                if len(filename) == 0:
                    filename = "Untitled_Peer"
                filename = "".join(filename.split(" "))
            filename = filename + "_" + config_name
            psk = ""
            if preshared_key != "":
                psk = "\nPresharedKey = " + preshared_key

            return_data = (
                "[Interface]\nPrivateKey = "
                + private_key
                + "\nAddress = "
                + allowed_ip
                + "\nDNS = "
                + dns_addresses
                + "\nMTU = "
                + str(mtu_value)
                + "\n\n[Peer]\nPublicKey = "
                + public_key
                + "\nAllowedIPs = "
                + endpoint_allowed_ip
                + "\nEndpoint = "
                + endpoint
                + "\nPersistentKeepalive = "
                + str(keepalive)
                + psk
            )

            return jsonify(
                {"status": True, "filename": f"{filename}.conf", "content": return_data}
            )
    return jsonify({"status": False, "filename": "", "content": ""})


@app.route("/switch_display_mode/<mode>", methods=["GET"])
def switch_display_mode(mode):
    """
    Change display view style.

    @param mode: Mode name
    @type mode: str
    @return: Return text with result
    @rtype: str
    """

    if mode in ["list", "grid"]:
        config = read_dashboard_conf()
        config.set("Peers", "peer_display_mode", mode)
        write_dashboard_conf(config)
        config.clear()
        return "true"
    return "false"


"""
Dashboard Tools Related
"""


# Get all IP for ping
@app.route("/get_ping_ip", methods=["POST"])
def get_ping_ip():
    # TODO: convert return to json object

    """
    Get ips for network testing.
    @return: HTML containing a list of IPs
    """

    config = request.form["config"]
    peers = g.cur.execute(
        "SELECT id, name, allowed_ip, endpoint FROM " + config
    ).fetchall()
    html = ""
    for i in peers:
        html += '<optgroup label="' + i[1] + " - " + i[0] + '">'
        allowed_ip = str(i[2]).split(",")
        for k in allowed_ip:
            k = k.split("/")
            if len(k) == 2:
                html += "<option value=" + k[0] + ">" + k[0] + "</option>"
        endpoint = str(i[3]).split(":")
        if len(endpoint) == 2:
            html += "<option value=" + endpoint[0] + ">" + endpoint[0] + "</option>"
        html += "</optgroup>"
    return html


# Ping IP
@app.route("/ping_ip", methods=["POST"])
def ping_ip():
    """
    Execute ping command.
    @return: Return text with result
    @rtype: str
    """

    try:
        result = ping(
            "" + request.form["ip"] + "",
            count=int(request.form["count"]),
            privileged=True,
            source=None,
        )
        returnjson = {
            "address": result.address,
            "is_alive": result.is_alive,
            "min_rtt": result.min_rtt,
            "avg_rtt": result.avg_rtt,
            "max_rtt": result.max_rtt,
            "package_sent": result.packets_sent,
            "package_received": result.packets_received,
            "package_loss": result.packet_loss,
        }
        if returnjson["package_loss"] == 1.0:
            returnjson["package_loss"] = returnjson["package_sent"]
        return jsonify(returnjson)
    except Exception:
        return "Error"


# Traceroute IP
@app.route("/traceroute_ip", methods=["POST"])
def traceroute_ip():
    """
    Execute ping traceroute command.

    @return: Return text with result
    @rtype: str
    """

    try:
        result = traceroute(
            "" + request.form["ip"] + "", first_hop=1, max_hops=30, count=1, fast=True
        )
        returnjson = []
        last_distance = 0
        for hop in result:
            if last_distance + 1 != hop.distance:
                returnjson.append(
                    {"hop": "*", "ip": "*", "avg_rtt": "", "min_rtt": "", "max_rtt": ""}
                )
            returnjson.append(
                {
                    "hop": hop.distance,
                    "ip": hop.address,
                    "avg_rtt": hop.avg_rtt,
                    "min_rtt": hop.min_rtt,
                    "max_rtt": hop.max_rtt,
                }
            )
            last_distance = hop.distance
        return jsonify(returnjson)
    except Exception:
        return "Error"


"""
Dashboard Initialization
"""


def create_wg_server_keys_if_missing():
    """
    Creates /config/server/{private|public}key-server files if the private key is missing.
    """
    from pathlib import Path

    Path("/config/server").mkdir(parents=True, exist_ok=True)
    if not os.path.isfile(SERVER_PRIVATE_KEY_FILE):
        output = subprocess.check_output(
            f"wg genkey | tee /config/server/privatekey-server | wg pubkey > /config/server/publickey-server",
            shell=True,
        )


def wg_server_private_key() -> str:
    """
    Returns the contents of config/server/privatekey-server.
    """
    with open(SERVER_PRIVATE_KEY_FILE, "r") as f:
        key = f.readline()
    return key


def wg_server_public_key() -> str:
    """
    Returns the contents of config/server/publickey-server.
    """
    with open(SERVER_PUBLIC_KEY_FILE, "r") as f:
        key = f.readline()
    return key


def create_wg_server_config_if_missing():
    """
    Creates /config/wg0.conf if missing.
    """
    create_wg_server_keys_if_missing()
    subnet = read_dashboard_conf()["Server"]["internal_subnet"]
    interface = get_base_net(subnet)
    if not os.path.isfile(SERVER_CONFIG_FILE):
        rendered = render_template(
            "config_file_templates/server.jinja2",
            interface=interface,
            private_server_key=wg_server_private_key(),
        )
        with open(SERVER_CONFIG_FILE, "w") as f:
            f.writelines([rendered])


def get_base_net(ipv4: str | int) -> str:
    """
    Returns the first three octects of an IPv4 address
    """
    try:
        ipaddress.ip_address(ipv4)
    except:
        raise ValueError(
            f"Passed value of {ipv4} doesn't seem to be a valid IP address."
        )

    tokens = ipv4.split(".")
    return ".".join(tokens[0:3])


def init_dashboard():
    """
    Create dashboard default configuration.
    """

    # Set Default INI File
    if not os.path.isfile(DASHBOARD_CONF_FILE):
        open(DASHBOARD_CONF_FILE, "w+").close()
    config = read_dashboard_conf()
    # Default dashboard account setting
    if "Account" not in config:
        config["Account"] = {}
    if "username" not in config["Account"]:
        config["Account"]["username"] = "admin"
    if "password" not in config["Account"]:
        config["Account"][
            "password"
        ] = "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    # Default dashboard server setting
    if "Server" not in config:
        config["Server"] = {}
    if "wg_conf_path" not in config["Server"]:
        config["Server"]["wg_conf_path"] = "/config"
    if "auth_req" not in config["Server"]:
        config["Server"]["auth_req"] = "true"
    if (
        "version" not in config["Server"]
        or config["Server"]["version"] != DASHBOARD_VERSION
    ):
        config["Server"]["version"] = DASHBOARD_VERSION
    if "dashboard_refresh_interval" not in config["Server"]:
        config["Server"]["dashboard_refresh_interval"] = "60000"
    if "dashboard_sort" not in config["Server"]:
        config["Server"]["dashboard_sort"] = "status"
    if "internal_subnet" not in config["Server"]:
        # This takes inspiration from https://github.com/linuxserver/docker-wireguard/
        config["Server"]["internal_subnet"] = "10.13.13.0"
    # Default dashboard peers setting
    if "Peers" not in config:
        config["Peers"] = {}
    if "peer_global_DNS" not in config["Peers"]:
        # This takes inspiration from https://github.com/linuxserver/docker-wireguard/
        # If not set, set DNS to x.y.z.1 to use wireguard docker host's DNS
        config["Peers"][
            "peer_global_DNS"
        ] = f"{get_base_net(config['Server']['internal_subnet'])}.1"
    if "peer_endpoint_allowed_ip" not in config["Peers"]:
        config["Peers"]["peer_endpoint_allowed_ip"] = "0.0.0.0/0"
    if "peer_display_mode" not in config["Peers"]:
        config["Peers"]["peer_display_mode"] = "grid"
    if "remote_endpoint" not in config["Peers"]:
        config["Peers"]["remote_endpoint"] = ifcfg.default_interface()["inet"]
    if "peer_MTU" not in config["Peers"]:
        config["Peers"]["peer_MTU"] = "1420"
    if "peer_keep_alive" not in config["Peers"]:
        config["Peers"]["peer_keep_alive"] = "21"

    write_dashboard_conf(config)
    create_wg_server_config_if_missing()
    config.clear()


def check_update():
    """
    Dashboard check update

    @return: Retunt text with result
    @rtype: str
    """
    config = read_dashboard_conf()
    try:
        data = urllib.request.urlopen(
            "https://api.github.com/repos/donaldzou/WGDashboard/releases"
        ).read()
        output = json.loads(data)
        release = []
        for i in output:
            if not i["prerelease"]:
                release.append(i)
        if config.get("Server", "version") == release[0]["tag_name"]:
            result = "false"
        else:
            result = "true"

        return result
    except urllib.error.HTTPError:
        return "false"


"""
Configure DashBoard before start web-server
"""


def run_dashboard():
    init_dashboard()
    global UPDATE
    UPDATE = check_update()
    config = read_dashboard_conf()
    # global app_ip
    app_ip = config.get("Server", "app_ip")
    # global app_port
    app_port = config.get("Server", "app_port")
    config.clear()
    return app


"""
Get host and port for web-server
"""


def get_host_bind():
    init_dashboard()
    config = read_dashboard_conf()
    app_ip = config.get("Server", "app_ip")
    app_port = config.get("Server", "app_port")
    return app_ip, app_port


if __name__ == "__main__":
    init_dashboard()
    UPDATE = check_update()
    config = read_dashboard_conf()
    # global app_ip
    app_ip = config.get("Server", "app_ip")
    # global app_port
    app_port = config.get("Server", "app_port")
    config.clear()
    app.run(host=app_ip, debug=False, port=app_port)
