<?php
/*
 * pppoe_ha_event.php - CARP event handler with per-VHID suppression and end-of-window MASTER stabilization
 *
 * devd:
 *   /usr/local/sbin/pppoe_ha_event carp <subsystem> <MASTER|BACKUP>
 *     subsystem may be "5@igb0", "carp1", or "5"
 *
 * manual:
 *   /usr/local/sbin/pppoe_ha_event reconcile [vhid]
 *   /usr/local/sbin/pppoe_ha_event reconcile_quiet [vhid]
 */

require_once("util.inc");
require_once("config.inc");
require_once("interfaces.inc");
require_once("/usr/local/pkg/pppoe_ha.inc");

/* logging */
function ha_log($msg, $prio = LOG_NOTICE) {
    static $opened = false;
    if (!$opened) {
        openlog('pppoe-ha', LOG_PID, LOG_USER);
        $opened = true;
        register_shutdown_function(function() { closelog(); });
    }
    syslog($prio, $msg);
}
function ha_log_debug($msg) { ha_log($msg, LOG_DEBUG); }

/* constants */
const SUPPRESS_DIR           = '/var/run/pppoe_ha';
const STABILIZE_POLL_SEC     = 30;   // sleep granularity
const STABILIZE_SUPPRESS_SEC = 180;  // suppression window per VHID

/* utils */
function ppha_sanitize_token($s) {
    $s = trim((string)$s);
    if ($s !== '' && $s[0] === '$') { $s = substr($s, 1); }
    return $s;
}

/* per-VHID suppression storage */
function ppha_suppress_path(int $vhid) {
    @mkdir(SUPPRESS_DIR, 0755, true);
    return SUPPRESS_DIR . '/suppress.' . max(1, $vhid) . '.json';
}
function ppha_set_suppression(int $seconds, string $reason, int $vhid) {
    $path  = ppha_suppress_path($vhid);
    $until = time() + max(1, $seconds);
    $data  = ['until'=>$until, 'reason'=>$reason, 'vhid'=>$vhid];
    @file_put_contents($path, json_encode($data));
    ha_log("suppression on for {$seconds}s reason={$reason} vhid={$vhid}");
}
function ppha_clear_suppression(int $vhid) {
    $path = ppha_suppress_path($vhid);
    if (file_exists($path)) { @unlink($path); ha_log("suppression cleared vhid={$vhid}"); }
}
function ppha_read_suppression(int $vhid) {
    $path = ppha_suppress_path($vhid);
    if (!file_exists($path)) return null;
    $j = json_decode(@file_get_contents($path), true);
    return is_array($j) ? $j : null;
}
function ppha_get_suppression_remaining(int $vhid) {
    $j = ppha_read_suppression($vhid);
    if (!$j || empty($j['until'])) return 0;
    $rem = (int)$j['until'] - time();
    return ($rem > 0) ? $rem : 0;
}
function ppha_is_suppressed(int $vhid) {
    // used by event handler to ignore events. expire -> auto clear.
    $path = ppha_suppress_path($vhid);
    if (!file_exists($path)) return false;
    $j = json_decode(@file_get_contents($path), true);
    if (!is_array($j) || empty($j['until'])) return false;
    if (time() >= (int)$j['until']) { @unlink($path); return false; }
    return true;
}

/* spawn helper in background */
function spawn_bg(array $args) {
    $php  = PHP_BINARY ?: "/usr/local/bin/php";
    $self = escapeshellarg(realpath(__FILE__));
    $cmd  = $php . " -f " . $self . ' ' . implode(' ', array_map('escapeshellarg', $args)) . " >/dev/null 2>&1 &";
    mwexec($cmd);
}

/* build target list from package config */
function ppha_build_targets($only_vhid = null) {
    $rows = ppha_get_rows();
    $vips = config_get_path('virtualip/vip', []);
    $targets = [];
    if (!is_array($rows) || !is_array($vips)) { return []; }

    foreach ($rows as $i => $row) {
        $enabled = isset($row['enabled']) && strcasecmp((string)$row['enabled'], 'ON') === 0;
        $vipref  = array_key_exists('vipref', $row) ? (string)$row['vipref'] : '';
        $iface   = array_key_exists('iface',  $row) ? (string)$row['iface']  : '';
        if (!$enabled || $vipref === '' || $iface === '') { continue; }

        $vip = $vips[$vipref] ?? null;
        if (!$vip || ($vip['mode'] ?? '') !== 'carp') { continue; }
        $vhid = (int)($vip['vhid'] ?? -1);
        if ($vhid < 0) { continue; }
        if ($only_vhid !== null && (int)$only_vhid !== $vhid) { continue; }

        $real = get_real_interface($iface);
        if (empty($real)) {
            ha_log("row[$i] {$iface}/vipref={$vipref} - real interface not found; skipping");
            continue;
        }
        $targets[] = [
            'idx'            => (int)$i,
            'iface_friendly' => $iface,   // pfSense friendly name (wan)
            'iface_real'     => $real,    // real if (pppoeX)
            'vipref'         => $vipref,
            'vhid'           => $vhid,
        ];
    }
    return $targets;
}

/* parse CARP subsystem and read state */
function parse_carp_subsystem($subsys) {
    $subsys = ppha_sanitize_token($subsys);
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
function get_carp_state_for_vhid($vhid) {
    $vhid = (int)$vhid;
    $out = []; $rc = 0;
    @exec('/sbin/ifconfig -a', $out, $rc);
    if ($rc !== 0 || empty($out)) { return null; }
    foreach ($out as $line) {
        if (preg_match('/\bcarp:\s*(MASTER|BACKUP|INIT)\b.*\bvhid\s+(\d+)/i', $line, $m)) {
            if ((int)$m[2] === $vhid) { return strtoupper($m[1]); }
        }
    }
    return null;
}

/* PPPoE helpers */
function is_pppoe_real($ifname){ return (bool)preg_match('/^pppoe\d+$/', (string)$ifname); }
function real_iface_present($real){
    $out = []; $rc = 0;
    @exec("/sbin/ifconfig " . escapeshellarg($real) . " 2>/dev/null", $out, $rc);
    return ($rc === 0 && !empty($out));
}
function get_pppoe_status($real) {
    $out = [];
    @exec("/sbin/ifconfig " . escapeshellarg($real) . " 2>&1", $out);
    $up_flag = false; $running_flag = false; $has_v4_p2p = false; $has_v6_global = false;
    foreach ($out as $line) {
        if (preg_match('/flags=\S+<([^>]+)>/', $line, $m)) {
            $flags = explode(',', strtoupper($m[1]));
            $up_flag = in_array('UP', $flags, true) || $up_flag;
            $running_flag = in_array('RUNNING', $flags, true) || $running_flag;
        }
        if (preg_match('/^\s*inet\s+\S+\s+-->\s+\S+/', $line)) { $has_v4_p2p = true; continue; }
        if (preg_match('/^\s*inet6\s+([0-9a-f:]+)/i', $line, $m6)) {
            $addr = strtolower($m6[1]);
            if (strpos($addr, 'fe80:') !== 0 && stripos($line, 'tentative') === false) { $has_v6_global = true; }
        }
    }
    $ok = ($up_flag && $running_flag && ($has_v4_p2p || $has_v6_global)); // IPv4 or IPv6-only
    return [
        'up_flag'       => $up_flag,
        'running_flag'  => $running_flag,
        'has_ipv4_p2p'  => $has_v4_p2p,
        'has_v6_global' => $has_v6_global,
        'ok'            => $ok
    ];
}

/* pfSense iface ops */
function iface_up($friendly){
    $cmd = "/usr/local/sbin/pfSctl -c " . escapeshellarg("interface reload {$friendly}");
    mwexec($cmd);
}
function iface_down($real){
    mwexec("/sbin/ifconfig " . escapeshellarg($real) . " down");
}

/* apply one CARP state */
function ppha_apply_target_state(array $t, string $state) {
    $iface = $t['iface_friendly'];
    $real  = $t['iface_real'];
    $vhid  = $t['vhid'];

    if (!is_pppoe_real($real)) {
        ha_log("warn: {$real} is not pppoeX; continue");
    }

    switch ($state) {
        case 'MASTER':
            ha_log("VHID {$vhid} MASTER - up {$iface} ({$real})");
            if (real_iface_present($real)) {
                mwexec("/sbin/ifconfig " . escapeshellarg($real) . " up");
            } else {
                iface_up($iface);
            }
            ppha_set_suppression(STABILIZE_SUPPRESS_SEC, 'master_stabilize', $vhid);
            spawn_bg(['MASTER_POST', (string)$vhid, $iface, $real]);
            break;

        case 'BACKUP':
            ha_log("VHID {$vhid} BACKUP - down {$iface} ({$real})");
            iface_down($real);
            break;

        default:
            break;
    }
}

/* reconcile for one VHID (quiet reduces logs) */
function reconcile_target(int $vhid, bool $quiet=false) {
    $targets = ppha_build_targets($vhid);
    if (!$targets) { if (!$quiet) ha_log("reconcile: no mappings for VHID {$vhid}"); return; }

    foreach ($targets as $t) {
        $iface = $t['iface_friendly']; $real = $t['iface_real'];
        $state = get_carp_state_for_vhid($vhid) ?? 'INIT';

        if ($state === 'MASTER') {
            if (is_pppoe_real($real)) {
                $st = get_pppoe_status($real);
                if ($st['ok']) {
                    if (!$quiet) ha_log("reconcile: MASTER and PPPoE OK on {$real} - skip");
                    continue;
                }
            }
            if (!$quiet) ha_log("reconcile: MASTER - ensure {$iface} ready");
            iface_up($iface);

        } elseif ($state === 'BACKUP') {
            if (is_pppoe_real($real)) {
                $st = get_pppoe_status($real);
                if (!$st['up_flag'] || !$st['running_flag']) {
                    if (!$quiet) ha_log("reconcile: BACKUP and PPPoE already down on {$real} - skip");
                    continue;
                }
            }
            if (!$quiet) ha_log("reconcile: BACKUP - bring {$real} down");
            iface_down($real);

        } else {
            if (!$quiet) ha_log("reconcile: VHID {$vhid} state INIT - skip");
        }
    }
}

/* reconcile all distinct VHIDs */
function reconcile_all(bool $quiet=false) {
    $targets = ppha_build_targets(null);
    if (!$targets) { if (!$quiet) ha_log("reconcile: no mappings configured"); return; }
    $seen = [];
    foreach ($targets as $t) {
        $v = (int)$t['vhid'];
        if (isset($seen[$v])) continue;
        $seen[$v] = true;
        reconcile_target($v, $quiet);
    }
}

/* MASTER post sequence: act only at suppression end */
function master_post_sequence(int $vhid, string $iface, string $real) {
    ha_log("master_post: start for VHID {$vhid}");
    while (true) {
        $rem = ppha_get_suppression_remaining($vhid);
        if ($rem > 0) {
            $sleep = ($rem > STABILIZE_POLL_SEC) ? STABILIZE_POLL_SEC : $rem;
            if ($sleep > 0) { sleep($sleep); }
            continue;
        }

        $cur = get_carp_state_for_vhid($vhid);

        // CHANGE: if not MASTER at the end of the window, clear suppression and exit
        if ($cur !== 'MASTER') {
            ha_log("master_post: state={$cur} at end-of-window - clear suppression and exit vhid={$vhid}");
            ppha_clear_suppression($vhid);
            reconcile_target($vhid, true);
            return;
        }

        $pppoe_ok = true;
        if (is_pppoe_real($real) && real_iface_present($real)) {
            $st = get_pppoe_status($real);
            $pppoe_ok = $st['ok'];
        }

        if ($pppoe_ok) {
            ha_log("master_post: end-of-window OK, clearing suppression vhid={$vhid}");
            ppha_clear_suppression($vhid);
            return;
        }

        ha_log_debug("master_post: end-of-window not OK (state={$cur} ok=" . ($pppoe_ok ? '1' : '0') . ") reconcile and extend");
        reconcile_target($vhid, true);
        ppha_set_suppression(STABILIZE_SUPPRESS_SEC, 'master_stabilize', $vhid);
        // loop will sleep until the next window end
    }
}

/* event dispatch (ignore if suppressed for this VHID) */
function handle_carp_state_change($vhid, $state) {
    if (ppha_is_suppressed((int)$vhid)) {
        ha_log("CARP event suppressed: VHID {$vhid} state={$state}");
        return;
    }
    $targets = ppha_build_targets($vhid);
    if (!$targets) { ha_log("no mappings for VHID {$vhid}; ignore"); return; }
    foreach ($targets as $t) { ppha_apply_target_state($t, $state); }
}

/* main */
function main_entry($argv) {
    array_shift($argv);
    $cmd = strtoupper($argv[0] ?? '');

    if ($cmd === 'CARP') {
        $subsys = ppha_sanitize_token($argv[1] ?? '');
        $state  = strtoupper(ppha_sanitize_token($argv[2] ?? ''));
        $info   = parse_carp_subsystem($subsys);
        $vhid   = $info['vhid'];
        ha_log("Handle CARP command for {$subsys} - {$state}");
        if ($vhid === null || !in_array($state, ['MASTER','BACKUP'], true)) {
            ha_log("Invalid CARP args: subsystem={$subsys} parsed_vhid=".var_export($vhid,true)." state={$state}");
            exit(1);
        }
        handle_carp_state_change($vhid, $state);
        exit(0);
    }

    if ($cmd === 'RECONCILE') {
        $arg_vhid = (int)($argv[1] ?? 0);
        if ($arg_vhid > 0) { reconcile_target($arg_vhid, false); }
        else { reconcile_all(false); }
        exit(0);
    }

    if ($cmd === 'RECONCILE_QUIET') {
        $arg_vhid = (int)($argv[1] ?? 0);
        if ($arg_vhid > 0) { reconcile_target($arg_vhid, true); }
        else { reconcile_all(true); }
        exit(0);
    }

    if ($cmd === 'MASTER_POST') {
        $vhid = (int)($argv[1] ?? 0);
        $iface = (string)($argv[2] ?? '');
        $real  = (string)($argv[3] ?? '');
        if ($vhid <= 0 || $iface === '' || $real === '') { exit(1); }
        master_post_sequence($vhid, $iface, $real);
        exit(0);
    }

    echo "Usage:\n";
    echo "  pppoe_ha_event carp <vhid|carpX|vhid@realif> <MASTER|BACKUP>\n";
    echo "  pppoe_ha_event reconcile [vhid]\n";
    echo "  pppoe_ha_event reconcile_quiet [vhid]\n";
    exit(1);
}

/* run */
main_entry($argv);
