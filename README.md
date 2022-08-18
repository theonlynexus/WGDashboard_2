

##### Known issues on WGDashboard
- IPv6 in WireGuard not fully supoprted

<hr>
<p align="center">
  <img alt="WGDashboard" src="img/logo.png" width="128">
</p>

# WGDashboard-2

This is a fork of Donald Zou's [original implementation](https://github.com/donaldzou/wireguard-dashboard/). I tried submitting a PR, but Donald seems to be busy with life... I happend to have a little more spare time... and decided to take things in my own hands.

Goals of this form:

1. More structure and cleaner code
2. Multiple implementations with feature parity but different stacks (e.g. Flask/FastAPI, JQuery/Vue, etc.) to serve as educational content
2. Docker, Docker, Docker
3. Self-provisioning capabilities similar to [firezone](https://www.firezone.dev/)


## Table of Content


- [WGDashboard 2](#wgdashboard-2)
  - [🛒 Dependencies](#-dependencies)
  - [✨ Contributors](#-contributors)

## Requirements (local install)

**WireGuard** and **WireGuard-Tools (`wg-quick`)**, please refer to the 
[offical documentation](https://www.wireguard.com/install/).

- Configuration files under **`/etc/wireguard`**, but please note the following sample

  ```ini
  [Interface]
  ...
  SaveConfig = true
  # Need to include this line to allow WireGuard Tool to save your configuration, 
  # or if you just want it to monitor your WireGuard Interface and don't need to
  # make any changes with the dashboard, you can set it to false.
  
  [Peer]
  PublicKey = abcd1234
  AllowedIPs = 1.2.3.4/32
  # Must have for each peer
  ```

- Python 3.7+ & Pip3

- Browser support CSS3 and ES6

## 🛠 Install

### Locally
1. Download WGDashboard

   ```bash
   git clone -b v3.0.6 https://github.com/donaldzou/WGDashboard.git wgdashboard
   
2. Open the WGDashboard folder

   ```bash
   cd wgdashboard/src
   ```
   
3. Install WGDashboard

   ```bash
   sudo chmod u+x wgd.sh
   sudo ./wgd.sh install
   ```

4. Give read and execute permission to root of the WireGuard configuration folder, you can change the path if your configuration files are not stored in `/etc/wireguard`

   ```shell
   sudo chmod -R 755 /etc/wireguard
   ```

5. Run WGDashboard

   ```shell
   ./wgd.sh start
   ```
   
   **Note**:

   > For [`pivpn`](https://github.com/pivpn/pivpn) user, please use `sudo ./wgd.sh start` to run if your current account does not have the permission to run `wg show` and `wg-quick`.

6. Access dashboard

   Access your server with port `10086` (e.g. http://your_server_ip:10086), using username `admin` and password `admin`. See below how to change port and ip that the dashboard is running with.

### Docker



## 🪜 Usage

#### Start/Stop/Restart WGDashboard


```shell
cd wgdashboard/src
-----------------------------
./wgd.sh start    # Start the dashboard in background
-----------------------------
./wgd.sh debug    # Start the dashboard in foreground (debug mode)
-----------------------------
./wgd.sh stop     # Stop the dashboard
-----------------------------
./wgd.sh restart  # Restart the dasboard
```

#### Autostart WGDashboard on boot (>= v2.2)

In the `src` folder, it contained a file called `wg-dashboard.service`, we can use this file to let our system to autostart the dashboard after reboot. The following guide has tested on **Ubuntu**, most **Debian** based OS might be the same, but some might not. Please don't hesitate to provide your system if you have tested the autostart on another system.

1. Changing the directory to the dashboard's directory

   ```shell
   cd wgdashboard/src
   ```

2. Get the full path of the dashboard's directory

   ```shell
   pwd
   #Output: /root/wgdashboard/src
   ```

   For this example, the output is `/root/wireguard-dashboard/src`, your path might be different since it depends on where you downloaded the dashboard in the first place. **Copy the the output to somewhere, we will need this in the next step.**

3. Edit the service file, the service file is located in `wireguard-dashboard/src`, you can use other editor you like, here will be using `nano`

   ```shell
   nano wg-dashboard.service
   ```

   You will see something like this:

   ```ini
   [Unit]
   After=network.service
   
   [Service]
   WorkingDirectory=<your dashboard directory full path here>
   ExecStart=/usr/bin/python3 <your dashboard directory full path here>/dashboard.py
   Restart=always
   
   
   [Install]
   WantedBy=default.target
   ```

   Now, we need to replace both `<your dashboard directory full path here>` to the one you just copied from step 2. After doing this, the file will become something like this, your file might be different:

   ```ini
   [Unit]
   After=netword.service
   
   [Service]
   WorkingDirectory=/root/wgdashboard/src
   ExecStart=/usr/bin/python3 /root/wgdashboard/src/dashboard.py
   Restart=always
   
   
   [Install]
   WantedBy=default.target
   ```

   **Be aware that after the value of `WorkingDirectory`, it does not have  a `/` (slash).** And then save the file after you edited it

4. Copy the service file to systemd folder

   ```bash
   $ cp wg-dashboard.service /etc/systemd/system/wg-dashboard.service
   ```

   To make sure you copy the file successfully, you can use this command `cat /etc/systemd/system/wg-dashboard.service` to see if it will output the file you just edited.

5. Enable the service

   ```bash
   $ sudo chmod 664 /etc/systemd/system/wg-dashboard.service
   $ sudo systemctl daemon-reload
   $ sudo systemctl enable wg-dashboard.service
   $ sudo systemctl start wg-dashboard.service  # <-- To start the service
   ```

6. Check if the service run correctly

   ```bash
   $ sudo systemctl status wg-dashboard.service
   ```

   And you should see something like this

   ```shell
   ● wg-dashboard.service
        Loaded: loaded (/etc/systemd/system/wg-dashboard.service; enabled; vendor preset: enabled)
        Active: active (running) since Tue 2021-08-03 22:31:26 UTC; 4s ago
      Main PID: 6602 (python3)
         Tasks: 1 (limit: 453)
        Memory: 26.1M
        CGroup: /system.slice/wg-dashboard.service
                └─6602 /usr/bin/python3 /root/wgdashboard/src/dashboard.py
   
   Aug 03 22:31:26 ubuntu-wg systemd[1]: Started wg-dashboard.service.
   Aug 03 22:31:27 ubuntu-wg python3[6602]:  * Serving Flask app "WGDashboard" (lazy loading)
   Aug 03 22:31:27 ubuntu-wg python3[6602]:  * Environment: production
   Aug 03 22:31:27 ubuntu-wg python3[6602]:    WARNING: This is a development server. Do not use it in a production deployment.
   Aug 03 22:31:27 ubuntu-wg python3[6602]:    Use a production WSGI server instead.
   Aug 03 22:31:27 ubuntu-wg python3[6602]:  * Debug mode: off
   Aug 03 22:31:27 ubuntu-wg python3[6602]:  * Running on all addresses.
   Aug 03 22:31:27 ubuntu-wg python3[6602]:    WARNING: This is a development server. Do not use it in a production deployment.
   Aug 03 22:31:27 ubuntu-wg python3[6602]:  * Running on http://0.0.0.0:10086/ (Press CTRL+C to quit)
   ```

   If you see `Active:` followed by `active (running) since...` then it means it run correctly. 

7. Stop/Start/Restart the service

   ```bash
   sudo systemctl stop wg-dashboard.service      # <-- To stop the service
   sudo systemctl start wg-dashboard.service     # <-- To start the service
   sudo systemctl restart wg-dashboard.service   # <-- To restart the service
   ```

8. **And now you can reboot your system, and use the command at step 6 to see if it will auto start after the reboot, or just simply access the dashboard through your browser. If you have any questions or problem, please report it in the issue page.**

## ✂️ Dashboard Configuration

#### Dashboard Configuration file

Since version 2.0, WGDashboard will be using a configuration file called `wg-dashboard.ini`, (It will generate automatically after first time running the dashboard). More options will include in future versions, and for now it included the following configurations:

|                              | Description                                                                                                                                                                                              | Default                                              | Edit Available |
| ---------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- | -------------- |
| **`[Account]`**              | *Configuration on account*                                                                                                                                                                               |                                                      |                |
| `username`                   | Dashboard login username                                                                                                                                                                                 | `admin`                                              | Yes            |
| `password`                   | Password, will be hash with SHA256                                                                                                                                                                       | `admin` hashed in SHA256                             | Yes            |
|                              |                                                                                                                                                                                                          |                                                      |                |
| **`[Server]`**               | *Configuration on dashboard*                                                                                                                                                                             |                                                      |                |
| `wg_conf_path`               | The path of all the Wireguard configurations                                                                                                                                                             | `/etc/wireguard`                                     | Yes            |
| `app_ip`                     | IP address the dashboard will run with                                                                                                                                                                   | `0.0.0.0`                                            | Yes            |
| `app_port`                   | Port the the dashboard will run with                                                                                                                                                                     | `10086`                                              | Yes            |
| `auth_req`                   | Does the dashboard need authentication to access, if `auth_req = false` , user will not be access the **Setting** tab due to security consideration. **User can only edit the file directly in system**. | `true`                                               | **No**         |
| `version`                    | Dashboard Version                                                                                                                                                                                        | `v3.0.6`                                             | **No**         |
| `dashboard_refresh_interval` | How frequent the dashboard will refresh on the configuration page                                                                                                                                        | `60000ms`                                            | Yes            |
| `dashboard_sort`             | How configuration is sorting                                                                                                                                                                             | `status`                                             | Yes            |
|                              |                                                                                                                                                                                                          |                                                      |                |
| **`[Peers]`**                | *Default Settings on a new peer*                                                                                                                                                                         |                                                      |                |
| `peer_global_dns`            | DNS Server                                                                                                                                                                                               | `1.1.1.1`                                            | Yes            |
| `peer_endpoint_allowed_ip`   | Endpoint Allowed IP                                                                                                                                                                                      | `0.0.0.0/0`                                          | Yes            |
| `peer_display_mode`          | How peer will display                                                                                                                                                                                    | `grid`                                               | Yes            |
| `remote_endpoint`            | Remote Endpoint (i.e where your peers will connect to)                                                                                                                                                   | *depends on your server's default network interface* | Yes            |
| `peer_mtu`                   | Maximum Transmit Unit                                                                                                                                                                                    | `1420`                                               |                |
| `peer_keep_alive`            | Keep Alive                                                                                                                                                                                               | `21`                                                 | Yes            |

#### Generating QR code and peer configuration file (.conf)

Starting version 2.2, dashboard can now generate QR code and configuration file for each peer. Here is a template of what each QR code encoded with and the same content will be inside the file:

```ini
[Interface]
PrivateKey = QWERTYUIOPO234567890YUSDAKFH10E1B12JE129U21=
Address = 0.0.0.0/32
DNS = 1.1.1.1

[Peer]
PublicKey = QWERTYUIOPO234567890YUSDAKFH10E1B12JE129U21=
AllowedIPs = 0.0.0.0/0
Endpoint = 0.0.0.0:51820
```

|                   | Description                                                                                            | Default Value                                                                                   | Available in Peer setting |
| ----------------- | ------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------- | ------------------------- |
| **`[Interface]`** |                                                                                                        |                                                                                                 |                           |
| `PrivateKey`      | The private key of this peer                                                                           | Private key generated by WireGuard (`wg genkey`) or provided by user                            | Yes                       |
| `Address`         | The `allowed_ips` of your peer                                                                         | N/A                                                                                             | Yes                       |
| `DNS`             | The DNS server your peer will use                                                                      | `1.1.1.1` - Cloud flare DNS, you can change it when you adding the peer or in the peer setting. | Yes                       |
| **`[Peer]`**      |                                                                                                        |                                                                                                 |                           |
| `PublicKey`       | The public key of your server                                                                          | N/A                                                                                             | No                        |
| `AllowedIPs`      | IP ranges for which a peer will route traffic                                                          | `0.0.0.0/0` - Indicated a default route to send all internet and VPN traffic through that peer. | Yes                       |
| `Endpoint`        | Your wireguard server ip and port, the dashboard will search for your server's default interface's ip. | `<your server default interface ip>:<listen port>`                                              | Yes                       |

## ❓ How to update the dashboard?

### Local install

### Docker

## 🥘 Experimental Functions

#### Progressive Web App (PWA) for WGDashboard

- With `v3.0`, I've added a `manifest.json` into the dashboard, so user could add their dashboard as a PWA to their browser or mobile device.

<img src="img/PWA.gif"/>


## 🛒 Dependencies

- CSS/JS
  - [Bootstrap](https://getbootstrap.com/docs/4.6/getting-started/introduction/) `v4.6.0`
  - [Bootstrap Icon](https://icons.getbootstrap.com) `v1.4.0`
  - [jQuery](https://jquery.com) `v3.5.1`
- Python
  - [Flask](https://pypi.org/project/Flask/) `v2.0.1`
  - [ifcfg](https://pypi.org/project/ifcfg/) `v0.21`
  - [icmplib](https://pypi.org/project/icmplib/) `v2.1.1`
  - [flask-qrcode](https://pypi.org/project/Flask-QRcode/) `v3.0.0`****

## ✨ Contributors

<!-- ALL-CONTRIBUTORS-BADGE:START - Do not remove or modify this section -->

<!-- ALL-CONTRIBUTORS-BADGE:END -->

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- ALL-CONTRIBUTORS-LIST:START - Do not remove or modify this section -->

<!-- ALL-CONTRIBUTORS-LIST:END -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

