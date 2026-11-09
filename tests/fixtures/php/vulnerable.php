<?php
add_action('wp_ajax_nopriv_update_cart', 'update_cart');
$wpdb->query('SELECT * FROM users WHERE id=' . $_GET['id']);
echo $_GET['name'];
