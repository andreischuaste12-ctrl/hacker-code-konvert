<?php
function shop_save_settings() {
    update_option('shop_last_run', time());
}
