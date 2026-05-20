<?php

declare(strict_types=1);

require __DIR__ . '/../src/DomainContinuityGuard.php';

use DomainContinuityGuard\DomainContinuityGuard;

$pdo = new PDO('mysql:host=127.0.0.1;dbname=dcg;charset=utf8mb4', 'dcg_user', 'dcg_password', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);

$guard = new DomainContinuityGuard($pdo, getenv('DCG_APP_SECRET') ?: 'change-me-in-production');

$domain = $argv[1] ?? 'example.dk';

// Step 1: create DNS challenge.
$challenge = $guard->createDnsChallenge($domain);
echo "Add this DNS TXT record:\n";
echo $challenge['txt_name'] . ' TXT "' . $challenge['txt_value'] . '"' . "\n\n";
echo "After DNS propagates, run your own verification endpoint with the token.\n";

// Step 2: create identity keypair. Store the private key securely.
$identity = $guard->createDomainIdentity();
echo "Private continuity key. Show once. Store securely:\n";
echo $identity['private_key_base64'] . "\n\n";
echo "Public key:\n";
echo $identity['public_key_base64'] . "\n";
