<?php
register_rest_route('shop/v1', '/orders', array(
    'methods' => 'GET',
    'callback' => 'shop_list_orders',
    'permission_callback' => 'shop_can_list_orders',
));
