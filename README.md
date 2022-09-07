
##### Known issues on WGDashboard

- IPv6 in WireGuard not fully supoprted

<hr>
<p align="center">
  <img alt="WGDashboard" src="img/logo.png" width="128">
</p>

# WGDashboard-2

This is a fork of Donald Zou's [original implementation](https://github.com/donaldzou/wireguard-dashboard/). I tried submitting a PR, but Donald seems to be busy with life, so I decided to fork his codebase.

Goals of this fork:

1. More structure and cleaner code
2. Multiple implementations with feature parity but different stacks (e.g. Flask/FastAPI, JQuery/Vue, etc.) to serve as educational content
2. Docker, Docker, Docker
3. Self-provisioning capabilities similar to [firezone](https://www.firezone.dev/)

## Table of Content

- [WGDashboard 2](#wgdashboard-2)
  - [🛒 Dependencies](#-dependencies)
  - [✨ Contributors](#-contributors)

## Requirements (local install)

**WireGuard** and **WireGuard-Tools (`wg-quick`)**, please refer to the [offical documentation](https://www.wireguard.com/install/).

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

   Access your server with port `10086` (e.g. <http://your_server_ip:10086>), using username `admin` and password `admin`. See below how to change port and ip that the dashboard is running with.

### Docker

   Coming soon...

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
