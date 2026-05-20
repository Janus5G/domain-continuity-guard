<?php

declare(strict_types=1);

require __DIR__ . '/../src/DomainContinuityGuard.php';

use DomainContinuityGuard\DomainContinuityGuard;

$pdo = new PDO('mysql:host=127.0.0.1;dbname=dcg;charset=utf8mb4', 'dcg_user', 'dcg_password', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);

$guard = new DomainContinuityGuard($pdo, getenv('DCG_APP_SECRET') ?: 'change-me-in-production');

$domain = $argv[1] ?? '';
$token = $argv[2] ?? '';
$publicKeyBase64 = $argv[3] ?? '';

if ($domain === '' || $token === '' || $publicKeyBase64 === '') {
    fwrite(STDERR, "Usage: php verify-and-register.php example.dk DNS_TOKEN PUBLIC_KEY_BASE64\n");
    exit(1);
}

if (!$guard->verifyDnsChallenge($domain, $token)) {
    fwrite(STDERR, "DNS verification failed.\n");
    exit(1);
}

$result = $guard->registerOrRotateDomainEpoch($domain, $publicKeyBase64, 'dns_txt');
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
