<?php

declare(strict_types=1);

require __DIR__ . '/../src/DomainContinuityGuard.php';

use DomainContinuityGuard\DomainContinuityGuard;

$pdo = new PDO('mysql:host=127.0.0.1;dbname=dcg;charset=utf8mb4', 'dcg_user', 'dcg_password', [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
]);

$guard = new DomainContinuityGuard($pdo, getenv('DCG_APP_SECRET') ?: 'change-me-in-production');

$accountId = $argv[1] ?? '';
$email = $argv[2] ?? '';

if ($accountId === '' || $email === '') {
    fwrite(STDERR, "Usage: php account-recovery-check.php ACCOUNT_ID user@example.dk\n");
    exit(1);
}

$result = $guard->canRecoverAccountByEmail($accountId, $email);
echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES) . "\n";
