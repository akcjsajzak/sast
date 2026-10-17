<?php
// Raw PHP example — intentionally vulnerable for SAST demonstration.

$conn = mysqli_connect('localhost', 'user', 'pass', 'db');

// 1. SQL injection
$id = $_GET['id'];
$sql = "SELECT * FROM users WHERE id = " . $id;
mysqli_query($conn, $sql);

// 2. Reflected XSS
$name = $_GET['name'];
echo "<h1>Welcome " . $name . "</h1>";

// 3. Command injection
$cmd = $_POST['cmd'];
system('ls ' . $cmd);

// 4. SSRF / arbitrary file read
$url = $_GET['url'];
echo file_get_contents($url);

// 5. Local file inclusion
$page = $_GET['page'];
include $page . '.php';

// 6. Insecure deserialization
$data = $_COOKIE['session'];
$obj = unserialize($data);

// 7. XXE
$xml = $_POST['xml'];
$doc = simplexml_load_string($xml);

// 8. LDAP injection
$user = $_GET['user'];
ldap_search($ldap, 'dc=example,dc=com', "(uid=" . $user . ")");

// 9. Sanitized (should NOT be flagged)
$safe = htmlspecialchars($_GET['msg'], ENT_QUOTES, 'UTF-8');
echo $safe;

// 10. Interprocedural
function render_template($content) {
    echo $content;
}
render_template($_GET['html']);
