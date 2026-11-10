<?php
echo '<a href="' . esc_url($_GET['url']) . '">open</a>';
echo '<input value="' . esc_attr($_GET['email']) . '">';
