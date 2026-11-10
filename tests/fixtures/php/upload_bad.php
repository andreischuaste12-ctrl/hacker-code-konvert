<?php
move_uploaded_file($_FILES['invoice']['tmp_name'], 'uploads/' . $_FILES['invoice']['name']);
