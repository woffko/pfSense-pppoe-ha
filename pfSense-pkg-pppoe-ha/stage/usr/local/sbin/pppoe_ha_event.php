<?php
/*
 * pppoe_ha_event.php — CARP event handler + reconcile
 * Usage from devd:
 *   /usr/local/sbin/pppoe_ha_event carp <subsystem> <MASTER|BACKUP|INIT>
 * Usage manual:
 *   /usr/local/sbin/pppoe_ha_event reconcile
 */

require_once("util.inc");
require_once("config.inc");
require_once("interfaces.inc");
require_once("/usr/local/pkg/pppoe_ha.inc");

//function ha_log($msg) { log_error("[pppoe-ha] " . $msg); }
function ha_log($msg, $prio = LOG_NOTICE) {
    static $opened = false;
    if (!$opened) {
        // LOG_USER lands in the main System log; LOG_PID adds [pid]
        openlog('pppoe-ha', LOG_PID, LOG_USER);
        $opened = true;
        register_shutdown_function(function() { closelog(); });
    }
    syslog($prio, $msg);
}

//function ha_log($msg) { log_error("[pppoe-ha] " . $msg); }
function ha_log_debug($msg) {
   ha_log($msg, LOG_DEBUG);
}

// devd may pass '$19@vtnet0.510' and '$BACKUP' when action uses '$subsystem' '$type'
function ppha_sanitize_token($s) {
    $s = trim((string)$s);
    if ($s !== '' && $s[0] === '$') {
        $s = substr($s, 1);
    }
    return $s;
}

/** Parse devd CARP “subsystem” (e.g. "5@igb0", "carp1", "5") */
function parse_carp_subsystem($subsys) {
    $subsys = trim((string)$subsys);
    if ($subsys !== '' && $subsys[0] === '$') {
        $subsys = substr($subsys, 1);
    }
    $subsys = trim((string)$subsys);
    if (preg_match('/^(\d+)\@([A-Za-z0-9_.:\-]+)$/', $subsys, $m)) {
        return ['vhid'=>(int)$m[1], 'real'=>$m[2], 'carpif'=>null];
    }
    if (preg_match('/^(carp\d+)$/', $subsys, $m)) {
        $carpif = $m[1];
        $out=[]; @exec("/sbin/ifconfig ".escapeshellarg($carpif)." 2>/dev/null",$out);
        $vhid=null; foreach ($out as $line) {
            if (preg_match('/\bvhid\s+(\d+)/', $line, $mm)) { $vhid=(int)$mm[1]; break; }
        }
        return ['vhid'=>$vhid, 'real'=>null, 'carpif'=>$carpif];
    }
    if (preg_match('/^\d+$/', $subsys)) { return ['vhid'=>(int)$subsys, 'real'=>null, 'carpif'=>null]; }
    return ['vhid'=>null, 'real'=>null, 'carpif'=>null];
}

/**
 * Return CARP state (MASTER|BACKUP|INIT) for a given VHID, or null if not found.
 * Works whether CARP appears under carpX: or under a real interface block.
 */
function get_carp_state_for_vhid($vhid) {
    $vhid = (int)$vhid;
    $out = [];
    $rc  = 0;
    @exec('/sbin/ifconfig -a', $out, $rc);
    if ($rc !== 0 || empty($out)) {
        return null;
    }
    foreach ($out as $line) {
        // Look for a line like: "carp: MASTER vhid 19 ..." (order can vary)
        if (preg_match('/\bcarp:\s*(MASTER|BACKUP|INIT)\b.*\bvhid\s+(\d+)/i', $line, $m)) {
            if ((int)$m[2] === $vhid) {
                return strtoupper($m[1]);
            }
        }
    }
    return null;
}


function real_ifname_for_friendly($friendly) {
    $real = get_real_interface($friendly);
    if (!empty($real)) return $real;
    $ifcfg = config_get_path("interfaces/{$friendly}/if", '');
    return $ifcfg ?: null;
}
function is_pppoe_real($ifname){ return (bool)preg_match('/^pppoe\d+$/', (string)$ifname); }
//function iface_up($real){ mwexec("/sbin/ifconfig ".escapeshellarg($real)." up"); }
// iface_up needs to use pfSctl and needs to be called with the iface name instead of the real interface
function iface_up($iface){ mwexec("/usr/local/sbin/pfSctl -c 'interface reload ".escapeshellarg($iface)."'"); }
function iface_down($real){ mwexec("/sbin/ifconfig ".escapeshellarg($real)." down"); }



function handle_carp_state_change($vhid, $state) {
    $rows = ppha_get_rows();
    ha_log_debug("Handle carp state change");
    ha_log_debug("rows_count=" . count($rows));

    if (!$rows) {
        ha_log("No mappings configured; ignoring CARP change for VHID {$vhid}/{$state}");
        return;
    }

    // Build match set of VIP indices for this VHID
    $vips = config_get_path('virtualip/vip', []);
    $match = [];
    foreach ((array)$vips as $idx => $vip) {
        if (($vip['mode'] ?? '') === 'carp' && (int)($vip['vhid'] ?? -1) === (int)$vhid) {
            $match[] = (string)$idx;
        }
    }
    ha_log_debug("vhid_matches=" . ($match ? implode(',', $match) : 'none'));
    if (!$match) {
        ha_log("No CARP VIP with VHID {$vhid}; ignoring");
        return;
    }

    foreach ($rows as $i => $row) {
        // Normalize + show what we got
        $enabled = isset($row['enabled']) && strcasecmp((string)$row['enabled'], 'ON') === 0;
        $vipref  = array_key_exists('vipref', $row) ? (string)$row['vipref'] : '';
        $iface   = array_key_exists('iface',  $row) ? (string)$row['iface']  : '';

        ha_log_debug("row[$i]: enabled=" . ($enabled ? 'ON' : var_export($row['enabled'] ?? null, true)) .
               " vipref=" . var_export($vipref, true) .
               " iface="  . var_export($iface, true));

        // IMPORTANT: allow '0' — only reject truly missing values
        if ($iface === '' || $vipref === '') {
            ha_log_debug("row[$i] skipped: missing iface or vipref");
            continue;
        }
        if (!$enabled) {
            ha_log("Skipping disabled interface $iface. No action taken");
            continue;
        }
        if (!in_array($vipref, $match, true)) {
            ha_log("No interface configured for vipref {$vipref}; skip");
            continue;
        }

        $real = real_ifname_for_friendly($iface);
        if (!$real) {
            ha_log_debug("{$iface}/vipref={$vipref} - real if not found; skip");
            continue;
        }
        if (!is_pppoe_real($real)) {
            ha_log("Warn: {$real} not pppoeX; proceeding anyway");
        }

        if ($state === 'MASTER') {
            ha_log("VHID {$vhid} MASTER -> UP {$iface} ({$real})");
            iface_up($iface);
        } elseif ($state === 'BACKUP') {
            ha_log("VHID {$vhid} BACKUP -> DOWN {$iface} ({$real})");
            iface_down($real);
        } elseif ($state === 'INIT') {
            ha_log("VHID {$vhid} INIT -> DOWN {$iface} ({$real})");
            iface_down($real);
        } else {
            ha_log("VHID {$vhid} {$state} -> no action");
        }
    }

    ha_log_debug("end Handle carp state change");
}


function reconcile_all() {
    $rows = ppha_get_rows();
    if (!$rows){ ha_log("Reconcile: no mappings configured"); return; }
    ha_log("Running reconcile for all configured mappings");
    $vips = config_get_path('virtualip/vip', []);
    foreach ($rows as $row) {
        if (empty($row['enabled']) || empty($row['vipref']) || empty($row['iface'])) continue;
        $vip = $vips[$row['vipref']] ?? null;
        if (!$vip || ($vip['mode'] ?? '')!=='carp') continue;
        $vhid = (int)($vip['vhid'] ?? -1); if ($vhid<0) continue;

        $state = get_carp_state_for_vhid($vhid) ?? 'INIT';
        $friendly = (string)$row['iface'];
        $real = real_ifname_for_friendly($friendly);
        if (!$real){ ha_log("Reconcile: {$friendly} real if not found; skip"); continue; }

        if ($state==='MASTER'){ ha_log("Reconcile: VHID {$vhid} MASTER - UP {$friendly} ({$real})"); iface_up($real); }
        elseif ($state==='BACKUP'){ ha_log("Reconcile: VHID {$vhid} BACKUP - DOWN {$friendly} ({$real})"); iface_down($real); }
        elseif ($state==='INIT'){ ha_log("Reconcile: VHID {$vhid} INIT - DOWN {$friendly} ({$real})"); iface_down($real); }
        else { ha_log("Reconcile: VHID {$vhid} {$state} - no action"); }
    }
}

/* entry */

$argv0 = array_shift($argv);           // script path
$cmd   = strtoupper($argv[0] ?? '');

if ($cmd === 'CARP') {
    //ha_log("Handling CARP command");
    $subsys = ppha_sanitize_token($argv[1] ?? '');
    $state  = strtoupper(ppha_sanitize_token($argv[2] ?? ''));
    $info   = parse_carp_subsystem(ppha_sanitize_token($subsys));
    $vhid   = $info['vhid'];
    //echo "CMD CARP subsys $subsy state $state info $info vhid $vhid";
    ha_log("Handle CARP command for $subsys - $state");
    if ($vhid === null || !in_array($state, ['MASTER','BACKUP','INIT'], true)) {
        ha_log("Invalid CARP args: subsystem={$subsys} parsed_vhid=".var_export($vhid,true)." state={$state}");
        exit(1);
    }
    handle_carp_state_change($vhid, $state);
    exit(0);
}
if ($cmd === 'RECONCILE') {
    reconcile_all();
    exit(0);
}

/* help */
echo "Usage:\n";
echo "  pppoe_ha_event carp <vhid|carpX|vhid@realif> <MASTER|BACKUP|INIT>\n";
echo "  pppoe_ha_event reconcile\n";
exit(1);
