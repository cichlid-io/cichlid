# cichlid

## swarm based threat detection and threat information sharing

- identify the source of local threats
- publish and maintain a list of local threat sources
- identify and maintain a list of trusted peers
- defend against local threat sources and peer threat sources

## installation

### build from source

#### dependencies

#### fedora

```bash
sudo dnf install \
  cairo-gobject-devel \
  javascriptcoregtk4.0-devel \
  libsoup-devel \
  rust-gdk-devel \
  rust-gdk-pixbuf-devel \
  rust-libsystemd-devel \
  rust-pango-devel \
  webkit2gtk4.0-devel
```

#### ubuntu

```bash
sudo apt-get install \
  librust-gdk-pixbuf-dev \
  libwebkit2gtk-4.0-dev
```

#### .deb distros

```bash
cargo build
cargo deb
sudo dpkg -i target/debian/cichlid_0.0.1_amd64.deb
```

- installs cichlid binary at `/usr/bin/cichlid`
- installs cichlid service at `/lib/systemd/system/cichlid.service`
- creates cichlid service configuration at `/etc/cichlid/cichlid.yml`
- creates a system-user named `cichlid`
  - grants the `cichlid` system-user access to the system journal
  - creates a *home* directory for the `cichlid` system-user at `/var/lib/cichlid`
- following installation, the service is *started* and *enabled* (will auto start on boot)

## usage

- stop/start/restart service
  ```bash
  sudo systemctl stop cichlid.service
  sudo systemctl start cichlid.service
  sudo systemctl restart cichlid.service
  ```

- observe service status
  ```bash
  systemctl status cichlid.service
  ```

- tail service logs
  ```bash
  journalctl -fu cichlid.service
  ```

## uninstall

- remove the package
  ```bash
  sudo dpkg --purge cichlid
  ```

- remove the configuration folder
  ```bash
  sudo rm -rf /etc/cichlid
  ```

- remove the cichlid system-user and home (/var/lib/cichlid) folder
  ```bash
  sudo deluser --remove-home cichlid
  ```
