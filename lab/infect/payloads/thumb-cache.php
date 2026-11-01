<?php
// LAB SAMPLE (inert): shaped like a typical uploads backdoor (key check,
// reversed and encoded strings) but it only answers a liveness marker.
$_k = 'c3luYy1jaGVjaw==';
$_f = strrev('edoced_46esab');
if (isset($_REQUEST['k']) && $_REQUEST['k'] === $_f($_k)) {
    header('Content-Type: text/plain');
    echo 'alive:' . md5(__FILE__);
    exit;
}
