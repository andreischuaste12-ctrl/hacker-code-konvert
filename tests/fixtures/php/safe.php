<?php
add_action('wp_ajax_update_cart', 'update_cart');
$wpdb->query($wpdb->prepare('SELECT * FROM users WHERE id=%d', $_GET['id']));
echo esc_html($_GET['name']);
