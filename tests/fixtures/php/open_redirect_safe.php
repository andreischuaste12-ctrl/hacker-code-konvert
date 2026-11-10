<?php
wp_safe_redirect(wp_validate_redirect($_GET['return_to'], home_url()));
