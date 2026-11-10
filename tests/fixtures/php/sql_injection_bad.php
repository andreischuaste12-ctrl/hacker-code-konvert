<?php
$orders = $wpdb->get_results("SELECT * FROM orders WHERE customer=" . $_REQUEST['customer']);
$total = $wpdb->get_var('SELECT total FROM orders WHERE id=' . $_COOKIE['order']);
$row = $wpdb->get_row($wpdb->prepare('SELECT * FROM orders WHERE id=' . $_GET['id']));
