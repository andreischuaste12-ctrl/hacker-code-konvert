<?php
$id = esc_sql($_GET['id']);
$wpdb->get_results("SELECT * FROM users WHERE id = " . $id);
