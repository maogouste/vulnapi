<?php
/**
 * VulnAPI - PHP Implementation
 *
 * Deliberately vulnerable API for security learning.
 * WARNING: This API contains intentional security vulnerabilities.
 * Do NOT deploy in production.
 */

// VULNERABILITY V08: CORS misconfiguration
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: *');
header('Access-Control-Allow-Headers: *');
header('Access-Control-Allow-Credentials: true');
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Configuration
define('JWT_SECRET', 'secret123'); // VULNERABILITY V02: Weak secret
define('MODE', getenv('VULNAPI_MODE') ?: 'challenge');
define('DB_PATH', __DIR__ . '/vulnapi.db');

// Initialize database
$db = new SQLite3(DB_PATH);
initDatabase($db);

// Router
$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = rtrim($uri, '/');

// Route handling
try {
    switch (true) {
        case $uri === '' || $uri === '/':
            echo json_encode([
                'name' => 'VulnAPI',
                'version' => '0.2.0',
                'mode' => MODE,
                'implementation' => 'PHP',
                'message' => 'Welcome to VulnAPI - A deliberately vulnerable API',
            ]);
            break;

        case $uri === '/health':
            echo json_encode(['status' => 'healthy', 'implementation' => 'php']);
            break;

        // Auth routes
        case $uri === '/api/register' && $method === 'POST':
            handleRegister($db);
            break;

        case $uri === '/api/login' && $method === 'POST':
            handleLogin($db);
            break;

        case $uri === '/api/me' && $method === 'GET':
            $user = requireAuth($db);
            echo json_encode($user);
            break;

        // Users routes
        case $uri === '/api/users' && $method === 'GET':
            handleListUsers($db);
            break;

        case preg_match('#^/api/users/(\d+)$#', $uri, $m) && $method === 'GET':
            handleGetUser($db, $m[1]);
            break;

        case preg_match('#^/api/users/(\d+)$#', $uri, $m) && $method === 'PUT':
            requireAuth($db);
            handleUpdateUser($db, $m[1]);
            break;

        case preg_match('#^/api/users/(\d+)$#', $uri, $m) && $method === 'DELETE':
            requireAuth($db);
            handleDeleteUser($db, $m[1]);
            break;

        // Legacy API V1 - VULNERABILITY V09
        case $uri === '/api/v1/users' && $method === 'GET':
            handleListUsersV1($db);
            break;

        case preg_match('#^/api/v1/users/(\d+)$#', $uri, $m) && $method === 'GET':
            handleGetUserV1($db, $m[1]);
            break;

        // Products routes
        case $uri === '/api/products' && $method === 'GET':
            handleListProducts($db);
            break;

        case preg_match('#^/api/products/(\d+)$#', $uri, $m) && $method === 'GET':
            handleGetProduct($db, $m[1]);
            break;

        // Tools routes
        case $uri === '/api/tools/ping' && $method === 'POST':
            requireAuth($db);
            handlePing();
            break;

        case $uri === '/api/tools/dns' && $method === 'POST':
            requireAuth($db);
            handleDns();
            break;

        case $uri === '/api/tools/debug' && $method === 'GET':
            handleDebug();
            break;

        // Flags routes
        case $uri === '/api/challenges' && $method === 'GET':
            handleListChallenges($db);
            break;

        case $uri === '/api/flags/submit' && $method === 'POST':
            requireAuth($db);
            handleSubmitFlag($db);
            break;

        // Docs routes
        case $uri === '/api/docs/mode':
            handleDocsMode();
            break;

        case $uri === '/api/docs/stats':
            handleDocsStats();
            break;

        case $uri === '/api/docs/categories':
            handleDocsCategories();
            break;

        case $uri === '/api/docs/vulnerabilities' && $method === 'GET':
            handleDocsVulnerabilities();
            break;

        case preg_match('#^/api/docs/vulnerabilities/([A-Z]\d+)$#', $uri, $m):
            handleDocsVulnerability($m[1]);
            break;

        // GraphQL
        case $uri === '/graphql' || $uri === '/graphql/':
            handleGraphQL($db);
            break;

        default:
            http_response_code(404);
            echo json_encode(['detail' => 'Not found']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => $e->getMessage()]);
}

// Database initialization
function initDatabase($db) {
    $db->exec("
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            is_active INTEGER DEFAULT 1,
            ssn TEXT,
            credit_card TEXT,
            secret_note TEXT,
            api_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            stock INTEGER DEFAULT 0,
            category TEXT,
            is_active INTEGER DEFAULT 1,
            internal_notes TEXT,
            supplier_cost REAL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS flags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            challenge_id TEXT UNIQUE NOT NULL,
            flag_value TEXT NOT NULL,
            description TEXT
        );
    ");

    // Seed if empty
    $result = $db->querySingle("SELECT COUNT(*) FROM users");
    if ($result == 0) {
        seedDatabase($db);
    }
}

function seedDatabase($db) {
    error_log("[*] Seeding database...");

    // Users - VULNERABILITY: weak bcrypt cost
    $users = [
        ['admin', 'admin@vulnapi.local', 'admin123', 'admin', '123-45-6789', '4111-1111-1111-1111', 'VULNAPI{bola_user_data_exposed}', 'admin-api-key-12345'],
        ['john', 'john@example.com', 'password123', 'user', '987-65-4321', '5500-0000-0000-0004', "John's private notes", null],
        ['jane', 'jane@example.com', 'jane2024', 'user', '456-78-9012', '3400-0000-0000-009', "Jane's secret data", null],
        ['bob', 'bob@example.com', 'bob', 'user', null, null, null, null],
        ['service_account', 'service@vulnapi.local', 'svc_password_2024', 'superadmin', null, null, 'Service account', 'VULNAPI{jwt_weak_secret_cracked}'],
    ];

    $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, role, ssn, credit_card, secret_note, api_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    foreach ($users as $u) {
        $hash = password_hash($u[2], PASSWORD_BCRYPT, ['cost' => 4]);
        $stmt->bindValue(1, $u[0]);
        $stmt->bindValue(2, $u[1]);
        $stmt->bindValue(3, $hash);
        $stmt->bindValue(4, $u[3]);
        $stmt->bindValue(5, $u[4]);
        $stmt->bindValue(6, $u[5]);
        $stmt->bindValue(7, $u[6]);
        $stmt->bindValue(8, $u[7]);
        $stmt->execute();
        $stmt->reset();
    }

    // Products
    $products = [
        ['Laptop Pro X1', 'High-performance laptop', 1299.99, 50, 'Electronics', 1, 'VULNAPI{exposure_internal_data_leak}', 850.00],
        ['Wireless Mouse', 'Ergonomic wireless mouse', 49.99, 200, 'Electronics', 1, 'Supplier: TechCorp', 20.00],
        ['USB-C Hub', '7-in-1 USB-C hub', 79.99, 150, 'Electronics', 1, 'Best seller Q4 2024', 35.00],
        ['Mechanical Keyboard', 'RGB mechanical keyboard', 149.99, 75, 'Electronics', 1, null, 80.00],
        ['4K Monitor', '27-inch 4K IPS monitor', 399.99, 30, 'Electronics', 1, 'Discontinued', 250.00],
        ['Secret Product', 'VULNAPI{sqli_database_dumped}', 9999.99, 1, 'Hidden', 0, 'Should never be visible', null],
    ];

    $stmt = $db->prepare("INSERT INTO products (name, description, price, stock, category, is_active, internal_notes, supplier_cost) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
    foreach ($products as $p) {
        $stmt->bindValue(1, $p[0]);
        $stmt->bindValue(2, $p[1]);
        $stmt->bindValue(3, $p[2]);
        $stmt->bindValue(4, $p[3]);
        $stmt->bindValue(5, $p[4]);
        $stmt->bindValue(6, $p[5]);
        $stmt->bindValue(7, $p[6]);
        $stmt->bindValue(8, $p[7]);
        $stmt->execute();
        $stmt->reset();
    }

    // Flags
    $flags = [
        ['V01', 'VULNAPI{bola_user_data_exposed}', 'BOLA vulnerability'],
        ['V02', 'VULNAPI{jwt_weak_secret_cracked}', 'Weak JWT secret'],
        ['V03', 'VULNAPI{exposure_internal_data_leak}', 'Data exposure'],
        ['V04', 'VULNAPI{ratelimit_bruteforce_success}', 'No rate limiting'],
        ['V05', 'VULNAPI{mass_assignment_privilege_escalation}', 'Mass assignment'],
        ['V06', 'VULNAPI{sqli_database_dumped}', 'SQL injection'],
        ['V07', 'VULNAPI{cmd_injection_rce_achieved}', 'Command injection'],
        ['V08', 'VULNAPI{misconfig_cors_headers_missing}', 'Security misconfiguration'],
        ['V09', 'VULNAPI{version_legacy_api_exposed}', 'Legacy API exposed'],
        ['V10', 'VULNAPI{logging_blind_attack_undetected}', 'Insufficient logging'],
        ['G01', 'VULNAPI{graphql_introspection_schema_leaked}', 'GraphQL introspection'],
        ['G02', 'VULNAPI{graphql_depth_resource_exhaustion}', 'Query depth DoS'],
        ['G03', 'VULNAPI{graphql_batch_rate_limit_bypass}', 'Batching attacks'],
        ['G04', 'VULNAPI{graphql_suggestions_field_enumeration}', 'Field suggestions'],
        ['G05', 'VULNAPI{graphql_authz_sensitive_data_exposed}', 'Auth bypass'],
    ];

    $stmt = $db->prepare("INSERT INTO flags (challenge_id, flag_value, description) VALUES (?, ?, ?)");
    foreach ($flags as $f) {
        $stmt->bindValue(1, $f[0]);
        $stmt->bindValue(2, $f[1]);
        $stmt->bindValue(3, $f[2]);
        $stmt->execute();
        $stmt->reset();
    }

    error_log("[*] Database seeded successfully!");
}

// JWT functions
function createToken($user) {
    $header = base64_encode(json_encode(['alg' => 'HS256', 'typ' => 'JWT']));
    $payload = base64_encode(json_encode([
        'sub' => $user['username'],
        'user_id' => $user['id'],
        'role' => $user['role'],
        'exp' => time() + 86400,
    ]));
    $signature = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));
    return "$header.$payload.$signature";
}

function parseToken($token) {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;

    [$header, $payload, $signature] = $parts;
    $expectedSig = base64_encode(hash_hmac('sha256', "$header.$payload", JWT_SECRET, true));

    if ($signature !== $expectedSig) return null;

    $data = json_decode(base64_decode($payload), true);
    if ($data['exp'] < time()) return null;

    return $data;
}

function getAuthUser($db) {
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+(.+)$/', $auth, $m)) return null;

    $payload = parseToken($m[1]);
    if (!$payload) return null;

    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bindValue(1, $payload['user_id']);
    $result = $stmt->execute();
    return $result->fetchArray(SQLITE3_ASSOC);
}

function requireAuth($db) {
    $user = getAuthUser($db);
    if (!$user) {
        http_response_code(401);
        echo json_encode(['detail' => 'Not authenticated']);
        exit;
    }
    return $user;
}

function getJsonBody() {
    return json_decode(file_get_contents('php://input'), true) ?? [];
}

// Auth handlers
function handleRegister($db) {
    $data = getJsonBody();
    $hash = password_hash($data['password'], PASSWORD_BCRYPT, ['cost' => 4]);

    $stmt = $db->prepare("INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, 'user')");
    $stmt->bindValue(1, $data['username']);
    $stmt->bindValue(2, $data['email']);
    $stmt->bindValue(3, $hash);

    if (!$stmt->execute()) {
        http_response_code(400);
        echo json_encode(['detail' => 'Username or email already exists']);
        return;
    }

    http_response_code(201);
    echo json_encode(['id' => $db->lastInsertRowID(), 'username' => $data['username'], 'email' => $data['email'], 'role' => 'user']);
}

function handleLogin($db) {
    $data = getJsonBody();

    $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
    $stmt->bindValue(1, $data['username']);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);

    if (!$user) {
        http_response_code(401);
        echo json_encode(['detail' => 'User not found']); // VULNERABILITY: User enumeration
        return;
    }

    if (!password_verify($data['password'], $user['password_hash'])) {
        http_response_code(401);
        echo json_encode(['detail' => 'Incorrect password']); // VULNERABILITY: User enumeration
        return;
    }

    $token = createToken($user);
    echo json_encode(['access_token' => $token, 'token_type' => 'bearer', 'user_id' => $user['id'], 'role' => $user['role']]);
}

// User handlers
function handleListUsers($db) {
    $results = $db->query("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key, created_at FROM users");
    $users = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $users[] = $row;
    }
    echo json_encode($users);
}

function handleGetUser($db, $id) {
    // VULNERABILITY V01: No authorization check
    $stmt = $db->prepare("SELECT id, username, email, role, is_active, ssn, credit_card, secret_note, api_key, created_at FROM users WHERE id = ?");
    $stmt->bindValue(1, $id);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);

    if (!$user) {
        http_response_code(404);
        echo json_encode(['detail' => 'User not found']);
        return;
    }

    echo json_encode($user);
}

function handleUpdateUser($db, $id) {
    $data = getJsonBody();

    // VULNERABILITY V05: Mass assignment
    foreach ($data as $field => $value) {
        if ($field === 'password') {
            $hash = password_hash($value, PASSWORD_BCRYPT, ['cost' => 4]);
            $db->exec("UPDATE users SET password_hash = '$hash' WHERE id = $id");
        } else {
            $db->exec("UPDATE users SET $field = '$value' WHERE id = $id");
        }
    }

    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bindValue(1, $id);
    $result = $stmt->execute();
    echo json_encode($result->fetchArray(SQLITE3_ASSOC));
}

function handleDeleteUser($db, $id) {
    $db->exec("DELETE FROM users WHERE id = $id");
    echo json_encode(['message' => 'User deleted']);
}

// Legacy API - VULNERABILITY V09
function handleListUsersV1($db) {
    $results = $db->query("SELECT * FROM users");
    $users = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $users[] = $row;
    }
    echo json_encode($users);
}

function handleGetUserV1($db, $id) {
    $stmt = $db->prepare("SELECT * FROM users WHERE id = ?");
    $stmt->bindValue(1, $id);
    $result = $stmt->execute();
    echo json_encode($result->fetchArray(SQLITE3_ASSOC));
}

// Products handlers
function handleListProducts($db) {
    $search = $_GET['search'] ?? '';

    if ($search) {
        // VULNERABILITY V06: SQL Injection
        $query = "SELECT * FROM products WHERE name LIKE '%$search%' OR description LIKE '%$search%'";
        $results = $db->query($query);
    } else {
        $results = $db->query("SELECT * FROM products WHERE is_active = 1");
    }

    $products = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $products[] = $row;
    }
    echo json_encode($products);
}

function handleGetProduct($db, $id) {
    $stmt = $db->prepare("SELECT * FROM products WHERE id = ?");
    $stmt->bindValue(1, $id);
    $result = $stmt->execute();
    echo json_encode($result->fetchArray(SQLITE3_ASSOC));
}

// Tools handlers
function handlePing() {
    $data = getJsonBody();
    $host = $data['host'] ?? '';

    // VULNERABILITY V07: Command injection
    $output = shell_exec("ping -c 1 $host 2>&1");

    echo json_encode([
        'success' => $output !== null,
        'command' => "ping -c 1 $host",
        'output' => $output,
    ]);
}

function handleDns() {
    $data = getJsonBody();
    $domain = $data['domain'] ?? '';

    // VULNERABILITY V07: Command injection
    $output = shell_exec("nslookup $domain 2>&1");

    echo json_encode(['domain' => $domain, 'output' => $output]);
}

function handleDebug() {
    // VULNERABILITY V08: Exposes sensitive debug info
    echo json_encode([
        'php_version' => PHP_VERSION,
        'env_vars' => $_ENV,
        'server' => $_SERVER,
    ]);
}

// Flags handlers
function handleListChallenges($db) {
    $results = $db->query("SELECT challenge_id, description FROM flags");
    $challenges = [];
    while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
        $challenges[] = [
            'id' => $row['challenge_id'],
            'description' => $row['description'],
            'category' => strpos($row['challenge_id'], 'G') === 0 ? 'graphql' : 'rest',
        ];
    }
    echo json_encode($challenges);
}

function handleSubmitFlag($db) {
    $data = getJsonBody();
    $flag = $data['flag'] ?? '';

    $stmt = $db->prepare("SELECT challenge_id, description FROM flags WHERE flag_value = ?");
    $stmt->bindValue(1, $flag);
    $result = $stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);

    if (!$row) {
        echo json_encode(['success' => false, 'message' => 'Invalid flag']);
        return;
    }

    echo json_encode([
        'success' => true,
        'message' => "Congratulations! You solved challenge {$row['challenge_id']}!",
        'challenge_id' => $row['challenge_id'],
    ]);
}

// Docs handlers
function handleDocsMode() {
    echo json_encode([
        'mode' => MODE,
        'documentation_enabled' => MODE === 'documentation',
        'description' => MODE === 'documentation'
            ? 'Documentation mode: Full exploitation details and remediation'
            : 'Challenge mode: Limited information, find vulnerabilities yourself',
    ]);
}

function loadVulnerabilities() {
    $path = __DIR__ . '/vulnerabilities.json';
    if (!file_exists($path)) return [];
    $data = json_decode(file_get_contents($path), true);
    return $data['vulnerabilities'] ?? [];
}

function handleDocsStats() {
    $vulns = loadVulnerabilities();
    $stats = [
        'total' => count($vulns),
        'by_severity' => [],
        'by_category' => [],
        'rest_api' => 0,
        'graphql' => 0,
    ];

    foreach ($vulns as $v) {
        $stats['by_severity'][$v['severity']] = ($stats['by_severity'][$v['severity']] ?? 0) + 1;
        $stats['by_category'][$v['category']] = ($stats['by_category'][$v['category']] ?? 0) + 1;
        if (strpos($v['id'], 'V') === 0) $stats['rest_api']++;
        else $stats['graphql']++;
    }

    echo json_encode($stats);
}

function handleDocsCategories() {
    $vulns = loadVulnerabilities();
    $categories = [];

    foreach ($vulns as $v) {
        $cat = $v['category'];
        if (!isset($categories[$cat])) {
            $categories[$cat] = ['name' => $cat, 'count' => 0, 'vulnerabilities' => []];
        }
        $categories[$cat]['count']++;
        $categories[$cat]['vulnerabilities'][] = $v['id'];
    }

    echo json_encode(array_values($categories));
}

function handleDocsVulnerabilities() {
    $vulns = loadVulnerabilities();
    $category = $_GET['category'] ?? '';
    $severity = $_GET['severity'] ?? '';

    $result = [];
    foreach ($vulns as $v) {
        if ($category && $v['category'] !== $category) continue;
        if ($severity && $v['severity'] !== $severity) continue;
        $result[] = [
            'id' => $v['id'],
            'name' => $v['name'],
            'category' => $v['category'],
            'severity' => $v['severity'],
            'owasp' => $v['owasp'],
            'cwe' => $v['cwe'],
            'description' => $v['description'],
        ];
    }

    echo json_encode($result);
}

function handleDocsVulnerability($id) {
    if (MODE !== 'documentation') {
        http_response_code(403);
        echo json_encode([
            'error' => 'Documentation mode is disabled',
            'message' => 'Set VULNAPI_MODE=documentation to access vulnerability details',
            'current_mode' => MODE,
        ]);
        return;
    }

    $vulns = loadVulnerabilities();
    foreach ($vulns as $v) {
        if ($v['id'] === $id) {
            echo json_encode($v);
            return;
        }
    }

    http_response_code(404);
    echo json_encode(['detail' => "Vulnerability $id not found"]);
}

// GraphQL handler (simplified)
function handleGraphQL($db) {
    $data = getJsonBody();
    $query = $data['query'] ?? '';

    // Simple GraphQL parser for basic queries
    if (strpos($query, '__schema') !== false) {
        // G01: Introspection enabled
        echo json_encode([
            'data' => [
                '__schema' => [
                    'types' => [
                        ['name' => 'User', 'fields' => [['name' => 'id'], ['name' => 'username'], ['name' => 'ssn'], ['name' => 'creditCard']]],
                        ['name' => 'Product', 'fields' => [['name' => 'id'], ['name' => 'name'], ['name' => 'internalNotes']]],
                    ],
                ],
            ],
        ]);
        return;
    }

    if (strpos($query, 'users') !== false) {
        // G05: No auth check
        $results = $db->query("SELECT id, username, email, role, ssn, credit_card, secret_note, api_key FROM users");
        $users = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $users[] = [
                'id' => $row['id'],
                'username' => $row['username'],
                'email' => $row['email'],
                'role' => $row['role'],
                'ssn' => $row['ssn'],
                'creditCard' => $row['credit_card'],
                'secretNote' => $row['secret_note'],
                'apiKey' => $row['api_key'],
            ];
        }
        echo json_encode(['data' => ['users' => $users]]);
        return;
    }

    if (strpos($query, 'products') !== false) {
        $results = $db->query("SELECT * FROM products");
        $products = [];
        while ($row = $results->fetchArray(SQLITE3_ASSOC)) {
            $products[] = [
                'id' => $row['id'],
                'name' => $row['name'],
                'description' => $row['description'],
                'price' => $row['price'],
                'internalNotes' => $row['internal_notes'],
                'supplierCost' => $row['supplier_cost'],
            ];
        }
        echo json_encode(['data' => ['products' => $products]]);
        return;
    }

    if (preg_match('/login.*username.*"([^"]+)".*password.*"([^"]+)"/', $query, $m)) {
        $stmt = $db->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bindValue(1, $m[1]);
        $result = $stmt->execute();
        $user = $result->fetchArray(SQLITE3_ASSOC);

        if ($user && password_verify($m[2], $user['password_hash'])) {
            $token = createToken($user);
            echo json_encode([
                'data' => [
                    'login' => [
                        'accessToken' => $token,
                        'tokenType' => 'bearer',
                        'userId' => $user['id'],
                        'role' => $user['role'],
                    ],
                ],
            ]);
        } else {
            echo json_encode(['errors' => [['message' => 'Invalid credentials']]]);
        }
        return;
    }

    echo json_encode(['data' => null, 'errors' => [['message' => 'Query not supported']]]);
}
