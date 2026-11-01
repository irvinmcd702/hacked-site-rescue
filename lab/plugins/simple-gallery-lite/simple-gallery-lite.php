<?php
/*
Plugin Name: Simple Gallery Lite
Description: Lightweight image galleries. (Fictional plugin for the rescue lab: it plays the outdated plugin the attacker came in through. Its upload endpoint is a stub that refuses every request.)
Version: 1.2.0
*/

add_shortcode('simple_gallery', function ($atts) {
    $atts = shortcode_atts(['ids' => ''], $atts);
    $ids = array_filter(array_map('absint', explode(',', $atts['ids'])));
    $out = '<div class="sg-gallery">';
    foreach ($ids as $id) {
        $out .= wp_get_attachment_image($id, 'medium');
    }
    return $out . '</div>';
});

// In the story this endpoint accepted uploads from anyone (no login, no nonce,
// no file-type check). In the lab it only exists so the trail can be followed.
add_action('wp_ajax_nopriv_sgl_upload_image', 'sgl_upload_image');
add_action('wp_ajax_sgl_upload_image', 'sgl_upload_image');
function sgl_upload_image() {
    wp_send_json_error('disabled in the lab', 403);
}
