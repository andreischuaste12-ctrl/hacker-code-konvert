<?php
$orders = $wpdb->get_results($wpdb->prepare('SELECT * FROM orders WHERE customer=%d', $_REQUEST['customer']));
$total = $wpdb->get_var('SELECT total FROM orders WHERE id=' . absint($_COOKIE['order']));
$row = $wpdb->get_row('SELECT * FROM orders WHERE id=' . (int) $_GET['id']);
