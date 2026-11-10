<?php
print esc_html($_REQUEST['coupon']);
printf('<p>%s</p>', esc_html($_GET['note']));
?>
<input value="<?= esc_attr($_POST['email']) ?>">
<a href="<?= esc_url($_GET['next']) ?>">next</a>
