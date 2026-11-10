<?php
$response = wp_remote_get('https://example.invalid/rates?currency=' . rawurlencode($_POST['currency']));
