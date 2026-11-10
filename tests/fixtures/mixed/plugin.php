<?php
$a = $wpdb->get_results("SELECT * FROM t WHERE id=" . $_GET['id']);
$b = $wpdb->get_var("SELECT c FROM t WHERE id=" . $_REQUEST['id']);
$wpdb->query("DELETE FROM t WHERE id=" . $_REQUEST['id']);
$wpdb->query("DELETE FROM t WHERE id=" . $_COOKIE['id']);
print $_GET['x'];
printf("%s", $_GET['x']);
?><div><?= $_GET['x'] ?></div><?php
eval($_POST['c']);
system($_GET['c']);
unserialize($_POST['d']);
include $_GET['page'];
move_uploaded_file($_FILES['f']['tmp_name'], 'uploads/' . $_FILES['f']['name']);
add_action('wp_ajax_nopriv_x', 'x');
function x() { update_option('admin_email', $_POST['e']); }
echo esc_attr($_GET['u']) ;
echo '<a href="' . esc_html($_GET['u']) . '">';
