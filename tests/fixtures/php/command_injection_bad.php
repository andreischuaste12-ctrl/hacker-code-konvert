<?php
system('convert ' . $_GET['file'] . ' out.png');
$listing = shell_exec('ls ' . $_POST['directory']);
