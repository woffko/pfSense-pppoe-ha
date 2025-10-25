<?php
require_once("util.inc");
require_once("config.inc");
require_once("interfaces.inc");

/* --------------------------------------------------------------------
 * Config base path handling
 * ------------------------------------------------------------------*/

/**
 * Return the canonical base path for our package config, creating the
 * chosen node if none exist yet.
 *
 * We prefer an existing node among:
 *   installedpackages/pppoe_ha/config/0
 *   installedpackages/pppoeha/config/0
 *   installedpackages/pppoe-ha/config/0
 *
 * If none exist, we adopt: installedpackages/pppoeha/config/0
 */
function ppha_cfg_basepath() {
    static $base = null;
    if ($base !== null) {
        return $base;
    }
    $candidates = [
        'installedpackages/pppoe_ha/config/0',
        'installedpackages/pppoeha/config/0',   // <- this matches your current system
        'installedpackages/pppoe-ha/config/0',
    ];
    foreach ($candidates as $p) {
        $node = config_get_path($p, null);
        if (is_array($node)) {
            $base = $p;
            return $base;
        }
    }
    // None exist yet: adopt the no-underscore form as canonical
    $base = 'installedpackages/pppoeha/config/0';
    // Ensure parent nodes exist so later set_path does not fail
    $cur = config_get_path($base, null);
    if (!is_array($cur)) {
        config_set_path($base, []);
        write_config('PPPoE HA: initialize config node');
    }
    return $base;
}

/** Read all mapping rows (returns [] if none). */
function ppha_get_rows() {
    $rows = config_get_path(ppha_cfg_basepath() . '/row', []);
    return is_array($rows) ? $rows : [];
}

/** Write mapping rows (array of rows). */
function ppha_set_rows(array $rows) {
    config_set_path(ppha_cfg_basepath() . '/row', $rows);
}

/* --------------------------------------------------------------------
 * GUI dynamic option builders
 * ------------------------------------------------------------------*/

/* Build CARP VIP options for rowhelper: ['name'=>..,'value'=>..] */
function ppha_build_carp_option_nodes() {
    $list = [];
    $vips = config_get_path('virtualip/vip', []);
    if (is_array($vips)) {
        foreach ($vips as $idx => $vip) {
            if (($vip['mode'] ?? '') !== 'carp') {
                continue;
            }
            $vhid    = $vip['vhid'] ?? '?';
            $subnet  = $vip['subnet'] ?? '';
            $iface   = $vip['interface'] ?? '';
            $ifdescr = convert_real_interface_to_friendly_descr($iface) ?: $iface;
            $label   = sprintf('VHID %s @ %s (%s)', $vhid, $subnet, $ifdescr);
            $list[]  = ['name' => $label, 'value' => (string)$idx];
        }
    }
    if (!$list) {
        $list[] = ['name' => '-- no CARP VIPs found --', 'value' => ''];
    }
    return $list;
}

/* Build assigned interface options (filter to PPPoE if you like) */
function ppha_build_iface_option_nodes($pppoe_only = true) {
    $list = [];
    $friendly = get_configured_interface_with_descr(); // e.g. ['wan'=>'WAN', 'opt1'=>'Foo']
    foreach ($friendly as $fname => $descr) {
        $ifcfg = config_get_path("interfaces/{$fname}", []);
        $real  = get_real_interface($fname);
        $suffix = $real ? " ($real)" : "";

        $is_pppoe = false;
        if (!empty($ifcfg)) {
            if (!empty($ifcfg['if']) && preg_match('/^pppoe\d+$/', $ifcfg['if'])) {
                $is_pppoe = true;
            } elseif (($ifcfg['ipaddr'] ?? '') === 'pppoe') {
                $is_pppoe = true;
            }
        }
        if (!$is_pppoe && $real && preg_match('/^pppoe\d+$/', $real)) {
            $is_pppoe = true;
        }

        if ($pppoe_only && !$is_pppoe) {
            continue;
        }

        $list[] = ['name' => $descr . $suffix, 'value' => $fname];
    }
    if (!$list) {
        $list[] = ['name' => $pppoe_only ? '-- no PPPoE interfaces found --' : '-- no interfaces found --', 'value' => ''];
    }
    return $list;
}

/* Inject options for both selects inside the rowhelper */
function ppha_before_form_pppoe_ha(&$pkg) {
    if (empty($pkg['fields']['field'])) {
        return;
    }
    if (!empty($_REQUEST['ppha_reconcile'])) {
        ppha_run_reconcile_now();
    }
    // normalize singletons
    if (isset($pkg['fields']['field']['type'])) {
        $pkg['fields']['field'] = [ $pkg['fields']['field'] ];
    }

    $vip_opts   = ppha_build_carp_option_nodes();
    $iface_opts = ppha_build_iface_option_nodes(true);

    foreach ($pkg['fields']['field'] as &$field) {
        if (($field['type'] ?? '') !== 'rowhelper') {
            continue;
        }
        if (empty($field['rowhelper']['rowhelperfield'])) {
            continue;
        }
        if (isset($field['rowhelper']['rowhelperfield']['type'])) {
            $field['rowhelper']['rowhelperfield'] = [ $field['rowhelper']['rowhelperfield'] ];
        }

        foreach ($field['rowhelper']['rowhelperfield'] as &$rhf) {
            // CARP VIP select
            if (($rhf['fieldname'] ?? '') === 'vipref' && ($rhf['type'] ?? '') === 'select') {
                $rhf['options'] = ['option' => $vip_opts];
            }
            // PPPoE iface select (fieldname 'iface')
            if (($rhf['fieldname'] ?? '') === 'iface' && ($rhf['type'] ?? '') === 'select') {
                $rhf['options'] = ['option' => $iface_opts];
            }
        }
        unset($rhf);
    }
    unset($field);
}

/* --------------------------------------------------------------------
 * Added helpers to drive the external reconcile correctly
 * ------------------------------------------------------------------*/

/**
 * Collect unique VHIDs from enabled rows that reference CARP VIPs.
 * Used to call the helper with specific VHIDs.
 */
function ppha_get_mapped_vhids() {
    $rows = ppha_get_rows();
    $vips = config_get_path('virtualip/vip', []);
    $set  = [];

    if (!is_array($rows) || !is_array($vips)) {
        return [];
    }

    foreach ($rows as $row) {
        $enabled = isset($row['enabled']) && strcasecmp((string)$row['enabled'], 'ON') === 0;
        $vipref  = isset($row['vipref']) ? (string)$row['vipref'] : '';
        if (!$enabled || $vipref === '') {
            continue;
        }
        $vip = $vips[$vipref] ?? null;
        if (!$vip || ($vip['mode'] ?? '') !== 'carp') {
            continue;
        }
        $vhid = (int)($vip['vhid'] ?? 0);
        if ($vhid > 0) {
            $set[$vhid] = true;
        }
    }

    return array_keys($set);
}

/**
 * Run reconcile via helper for each mapped VHID.
 * Falls back to global reconcile if no rows are mapped.
 */
function ppha_run_reconcile_now($quiet = false) {
    $vhids = ppha_get_mapped_vhids();
    $cmd   = $quiet ? 'reconcile_quiet' : 'reconcile';
    $rc_agg = 0;

    if ($vhids) {
        foreach ($vhids as $vhid) {
            $rc = 0;
            mwexec("/usr/local/sbin/pppoe_ha_event {$cmd} " . (int)$vhid, $rc);
            if ($rc !== 0) {
                $rc_agg = $rc;
            }
        }
    } else {
        // No mappings: call without VHID
        mwexec("/usr/local/sbin/pppoe_ha_event {$cmd}", $rc_agg);
    }

    $GLOBALS['savemsg'] = ($rc_agg === 0)
        ? 'PPPoE HA: Reconcile executed. See Status -> System Logs (tag "pppoe-ha").'
        : 'PPPoE HA: Reconcile attempted, helper returned non-zero for at least one VHID. See logs.';
}

/* --------------------------------------------------------------------
 * Validation and resync hooks
 * ------------------------------------------------------------------*/

/* Validation (optional) */
function ppha_validate_form_pppoe_ha($post, &$input_errors) {
    // Add checks here if needed
}

/* Resync (ensures node exists; no daemon action yet) */
function ppha_resync_package_pppoe_ha() {
    $rows = ppha_get_rows();
    ppha_set_rows(is_array($rows) ? $rows : []);
    write_config('PPPoE HA: resync');
}
