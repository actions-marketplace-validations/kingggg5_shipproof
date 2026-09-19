<?php
// Original polarity witness for research prototype SP5301. Not copied from an application.
if ($_FILES['upload']['type'] === 'image/png') {
    move_uploaded_file($tmp, $dst);
}
