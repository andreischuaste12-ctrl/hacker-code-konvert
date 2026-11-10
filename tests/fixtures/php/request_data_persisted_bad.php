<?php
add_action('wp_ajax_save_settings', 'shop_save_settings');
function shop_save_settings() {
    update_option('shop_admin_email', $_POST['email']);
}
