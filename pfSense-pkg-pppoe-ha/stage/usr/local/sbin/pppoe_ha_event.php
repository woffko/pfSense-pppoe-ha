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

function ppha_build_targets($only_vhid = null) {
    $rows = ppha_get_rows();
    $vips = config_get_path('virtualip/vip', []);
    $targets = [];

    if (!is_array($rows) || !is_array($vips)) {
        return [];
    }

    foreach ($rows as $i => $row) {
        // normalize; allow vipref '0'
        $enabled = isset($row['enabled']) && strcasecmp((string)$row['enabled'], 'ON') === 0;
        $vipref  = array_key_exists('vipref', $row) ? (string)$row['vipref'] : '';
        $iface   = array_key_exists('iface',  $row) ? (string)$row['iface']  : '';

        if (!$enabled || $vipref === '' || $iface === '') {
            ha_log_debug("row[$i] skipped (enabled/vipref/iface missing or off)");
            continue;
        }

        // resolve VIP + VHID
        $vip = $vips[$vipref] ?? null;
        if (!$vip || ($vip['mode'] ?? '') !== 'carp') {
            ha_log_debug("row[$i] skipped (vipref {$vipref} not CARP or missing)");
            continue;
        }
        $vhid = (int)($vip['vhid'] ?? -1);
        if ($vhid < 0) {
            ha_log_debug("row[$i] skipped (vipref {$vipref} has invalid VHID)");
            continue;
        }

        if ($only_vhid !== null && (int)$only_vhid !== $vhid) {
            continue;
        }

        // resolve interface
        $real = get_real_interface($iface);
        if (empty($real)) {
            ha_log("row[$i] {$iface}/vipref={$vipref} - real interface not found; skipping");
            continue;
        }

        $targets[] = [
            'idx'            => (int)$i,
            'iface_friendly' => $iface,
            'iface_real'     => $real,
            'vipref'         => $vipref,
            'vhid'           => $vhid,
        ];
    }

    return $targets;
}


/** Apply the CARP-derived state for a single target. */
function ppha_apply_target_state(array $t, string $state) {
    $iface = $t['iface_friendly'];
    $real  = $t['iface_real'];
    $vhid  = $t['vhid'];

    if (!is_pppoe_real($real)) {
        ha_log("warning: {$real} does not look like pppoeX; continuing anyway");
    }

    switch ($state) {
        case 'MASTER':
            ha_log("VHID {$vhid} MASTER - UP {$iface} ({$real})");
            //Call iface_up with $iface as it is using pfSctl internally!
            iface_up($iface);
            break;
        case 'BACKUP':
        case 'INIT':
            ha_log("VHID {$vhid} {$state} - DOWN {$iface} ({$real})");
            iface_down($real);
            break;
        default:
            ha_log("VHID {$vhid} {$state} - no action");
    }
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

function get_pppoe_status($real) {
    $out = [];
    @exec("/sbin/ifconfig " . escapeshellarg($real) . " 2>&1", $out);

    $has_v4_p2p = false;
    $has_v6_global = false;

    foreach ($out as $line) {
        // IPv4 PPPoE shows: inet <local> --> <peer>
        if (preg_match('/^\s*inet\s+\S+\s+-->\s+\S+/', $line)) {
            $has_v4_p2p = true;
            continue;
        }
        // IPv6 global (exclude link-local fe80:: and exclude 'tentative')
        if (preg_match('/^\s*inet6\s+([0-9a-f:]+)/i', $line, $m)) {
            $addr = strtolower($m[1]);
            if (strpos($addr, 'fe80:') !== 0 && stripos($line, 'tentative') === false) {
                $has_v6_global = true;
            }
        }
    }

    return [
        'active'       => ($has_v4_p2p || $has_v6_global),
        'has_ipv4_p2p' => $has_v4_p2p,
        'has_v6_global'=> $has_v6_global,
    ];
}

function is_pppoe_real($ifname){ return (bool)preg_match('/^pppoe\d+$/', (string)$ifname); }


// iface_up needs to use pfSctl and needs to be called with the iface name instead of the real interface!
function iface_up($iface){ mwexec("/usr/local/sbin/pfSctl -c 'interface reload ".escapeshellarg($iface)."'"); }
function iface_down($real){ mwexec("/sbin/ifconfig ".escapeshellarg($real)." down"); }



function handle_carp_state_change($vhid, $state) {
    ha_log_debug("carp change: vhid={$vhid} state={$state}");

    $targets = ppha_build_targets($vhid);
    if (!$targets) {
        ha_log("no mappings for VHID {$vhid}; ignoring");
        return;
    }
    foreach ($targets as $t) {
        ppha_apply_target_state($t, $state);
    }
}

function reconcile_all() {
    $targets = ppha_build_targets(); // all mappings
    if (!$targets) {
        ha_log("Reconcile: no mappings configured");
        return;
    }
    ha_log("Reconcile: evaluating " . count($targets) . " mapping(s)");
    foreach ($targets as $t) {
        $state = get_carp_state_for_vhid($t['vhid']) ?? 'INIT';
        $desired_up = ($state === 'MASTER');

        // Do not reload a PPPoE interface if it is already up and if the desired state also is up
        if (is_pppoe_real($t['iface_real'])) {
            $st = get_pppoe_status($t['iface_real']);
            if ($desired_up && $st['active']) {
                ha_log("Reconcile: VHID {$t['vhid']} target=UP but {$t['iface_friendly']} ({$t['iface_real']}) already UP - skip");
                continue;
            }
        }

        // Non-PPPoE (or PPPoE not active) - proceed as usual
        ppha_apply_target_state($t, $state);
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
