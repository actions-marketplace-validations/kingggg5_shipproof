<?php
// Authoritative Fileinfo check is outside the prototype's MIME-metadata signature.
$finfo = new finfo(FILEINFO_MIME_TYPE);
$mime = $finfo->file($_FILES['upload']['tmp_name']);
