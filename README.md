# pfSense-pkg-pppoe-ha  
**High Availability for dynamic PPPoE interfaces by using pfSense High Availability (CARP)**

## Why this package exists

pfSense supports two different PPPoE backends:  

- **Legacy `mpd` backend**  
  In this mode, it was possible to enable HA by binding a PPPoE interface directly to a CARP VIP.  

- **New `if_pppoe` backend (available since pfSense 2.8 / 25.07)**  
  This backend no longer allows binding PPPoE directly to a CARP VIP, breaking HA setups.  

**This package restores high availability for dynamic PPPoE interfaces.**  
It works by listening for CARP state changes of a specified CARP VHID which represents the state the current firewall should be in and enabling or disabling the configured PPPoE interface accordingly.  

If you still use legacy PPPoE (`mpd` backend), you can also use this package. In that case you don’t need to bind the PPPoE interface to a VIP – our package handles failover logic automatically.

---

## What it does

- On **CARP MASTER**: brings the PPPoE interface(s) **up** (`ifconfig up`)  
- On **CARP BACKUP/INIT**: brings the PPPoE interface(s) **down** (`ifconfig down`)
- GUI functionality to conveniently configure the WAN/PPPoE Interface(s) and the corresponding CARP groups

This ensures that only the current CARP master attempts the PPPoE session, avoiding duplicate sessions and ensuring clean failover.

---

## Features

- GUI page under **Services → PPPoE High Availability**  
  - Add rows mapping PPPoE interfaces to CARP VIPs.
- - `devd` integration to receive CARP updates.
- Still calls pfSense’s native CARP actions (`pfSctl`) so built-in behavior remains intact.
- One-shot **reconcile** command to sync PPPoE state with current CARP state after boot or install.
- Logs actions to syslog.

---

## How it works

**Installed components:**
- GUI definition: `/usr/local/pkg/pppoe_ha.xml`  
- GUI helper: `/usr/local/pkg/pppoe_ha.inc`  
- Event handler: `/usr/local/sbin/pppoe_ha_event.php` (+ launcher `/usr/local/sbin/pppoe_ha_event`)  
- `devd` rules: `/usr/local/etc/devd/pppoe_ha.conf` (priority **200**)  
- Optional GUI registration helper: `/usr/local/sbin/pppoe_ha_register_gui`

**Workflow:**
1. CARP changes state (`MASTER`, `BACKUP`, `INIT`)  
2. `devd` triggers `/usr/local/sbin/pppoe_ha_event carp <subsystem> <state>`  
3. Script finds matching PPPoE mappings in your config  
4. Interface is brought **up** or **down** as needed  

---

## Installation

### Build locally

```sh
# remove package if already installed
pkg delete -y pfSense-pkg-pppoe-ha-0.1

# build from source (run in repo root)
pkg create -m metadata -r stage -p pkg-plist -o .

# install generated pkg
pkg add ./pfSense-pkg-pppoe-ha-0.1.pkg
