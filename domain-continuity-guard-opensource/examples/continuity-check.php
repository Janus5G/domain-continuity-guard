<?php

declare(strict_types=1);

require __DIR__ . '/../src/DomainContinuityGuard.php';

use DomainContinuityGuard\DomainContinuityGuard;

$pdo = new PDO('mysql:host=127.0.0.1;dbname=dcg;charset=utf8mb4', 'dcg_user', 'dcg_password', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);

$guard = new DomainContinuityGuard($pdo, getenv('DCG_APP_SECRET') ?: 'change-me-in-production');

$domain = $argv[1] ?? 'example.dk';
$privateKey = $argv[2] ?? '';

$challenge = $guard->createContinuityChallenge($domain);
echo "Message to sign:\n" . $challenge['message_to_sign'] . "\n\n";

if ($privateKey === '') {
    echo "No private key passed. Send the challenge to the customer/client and verify the returned signature.\n";
    exit(0);
}

$signature = $guard->signContinuityChallenge($domain, $challenge['challenge'], $privateKey);
$ok = $guard->verifyContinuitySignature($domain, $challenge['challenge'], $signature);

echo $ok ? "Continuity proof accepted.\n" : "Continuity proof rejected.\n";
