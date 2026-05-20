<?php

declare(strict_types=1);

namespace DomainContinuityGuard;

use PDO;
use RuntimeException;

final class DomainContinuityGuard
{
    public function __construct(
        private PDO $pdo,
        private string $appSecret,
        private int $challengeTtlSeconds = 900
    ) {
        if (!extension_loaded('sodium')) {
            throw new RuntimeException('The sodium PHP extension is required.');
        }
    }

    public function normalizeDomain(string $domain): string
    {
        $domain = strtolower(trim($domain));
        $domain = rtrim($domain, '.');

        if ($domain === '' || strlen($domain) > 253 || !preg_match('/^[a-z0-9.-]+$/', $domain)) {
            throw new RuntimeException('Invalid domain.');
        }

        return $domain;
    }

    public function createDnsChallenge(string $domain): array
    {
        $domain = $this->normalizeDomain($domain);
        $token = $this->base64url(random_bytes(32));
        $tokenHash = hash_hmac('sha256', $token, $this->appSecret);
        $expiresAt = gmdate('Y-m-d H:i:s', time() + $this->challengeTtlSeconds);

        $stmt = $this->pdo->prepare(
            'INSERT INTO dcg_challenges (domain, purpose, token_hash, expires_at) VALUES (?, "dns_verify", ?, ?)'
        );
        $stmt->execute([$domain, $tokenHash, $expiresAt]);

        return [
            'domain' => $domain,
            'token' => $token,
            'txt_name' => '_dcg.' . $domain,
            'txt_value' => 'v=dcg1; token=' . $token,
            'expires_at_utc' => $expiresAt,
        ];
    }

    public function verifyDnsChallenge(string $domain, string $token): bool
    {
        $domain = $this->normalizeDomain($domain);
        $txtName = '_dcg.' . $domain;
        $expected = 'v=dcg1; token=' . $token;

        $records = dns_get_record($txtName, DNS_TXT);
        foreach ($records ?: [] as $record) {
            $txt = $record['txt'] ?? '';
            if (hash_equals($expected, $txt)) {
                return $this->consumeChallenge($domain, 'dns_verify', $token);
            }
        }

        return false;
    }

    public function createDomainIdentity(): array
    {
        $keyPair = sodium_crypto_sign_keypair();
        $privateKey = sodium_crypto_sign_secretkey($keyPair);
        $publicKey = sodium_crypto_sign_publickey($keyPair);

        return [
            'private_key_base64' => base64_encode($privateKey),
            'public_key_base64' => base64_encode($publicKey),
            'fingerprint' => hash('sha256', $publicKey),
        ];
    }

    public function registerOrRotateDomainEpoch(string $domain, string $publicKeyBase64, string $verificationMethod = 'dns_txt'): array
    {
        $domain = $this->normalizeDomain($domain);
        $publicKey = base64_decode($publicKeyBase64, true);
        if ($publicKey === false || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            throw new RuntimeException('Invalid public key.');
        }

        $fingerprint = hash('sha256', $publicKey);

        $this->pdo->beginTransaction();
        try {
            $domainId = $this->getOrCreateDomainId($domain);
            $current = $this->getCurrentEpochRowForUpdate($domainId);

            if ($current === null) {
                $epoch = 1;
            } else {
                $epoch = (int)$current['epoch'] + 1;
                $this->pdo->prepare('UPDATE dcg_domain_epochs SET status="superseded" WHERE domain_id=? AND status="active"')
                    ->execute([$domainId]);
                $this->pdo->prepare('UPDATE dcg_domains SET status="transferred_or_new_owner", current_epoch=? WHERE id=?')
                    ->execute([$epoch, $domainId]);
            }

            $stmt = $this->pdo->prepare(
                'INSERT INTO dcg_domain_epochs (domain_id, epoch, public_key_base64, public_key_fingerprint, verification_method, status)
                 VALUES (?, ?, ?, ?, ?, "active")'
            );
            $stmt->execute([$domainId, $epoch, $publicKeyBase64, $fingerprint, $verificationMethod]);

            $this->pdo->prepare('UPDATE dcg_domains SET current_epoch=?, status="active" WHERE id=?')
                ->execute([$epoch, $domainId]);

            $this->pdo->commit();

            return [
                'domain' => $domain,
                'epoch' => $epoch,
                'fingerprint' => $fingerprint,
                'status' => $epoch === 1 ? 'active' : 'new_epoch_created',
            ];
        } catch (\Throwable $e) {
            $this->pdo->rollBack();
            throw $e;
        }
    }

    public function createContinuityChallenge(string $domain): array
    {
        $domain = $this->normalizeDomain($domain);
        $token = $this->base64url(random_bytes(32));
        $tokenHash = hash_hmac('sha256', $token, $this->appSecret);
        $expiresAt = gmdate('Y-m-d H:i:s', time() + $this->challengeTtlSeconds);

        $stmt = $this->pdo->prepare(
            'INSERT INTO dcg_challenges (domain, purpose, token_hash, expires_at) VALUES (?, "continuity_proof", ?, ?)'
        );
        $stmt->execute([$domain, $tokenHash, $expiresAt]);

        return [
            'domain' => $domain,
            'challenge' => $token,
            'message_to_sign' => 'dcg1:continuity:' . $domain . ':' . $token,
            'expires_at_utc' => $expiresAt,
        ];
    }

    public function verifyContinuitySignature(string $domain, string $challengeToken, string $signatureBase64): bool
    {
        $domain = $this->normalizeDomain($domain);
        $epoch = $this->getCurrentEpoch($domain);
        if ($epoch === null) {
            return false;
        }

        $publicKey = base64_decode($epoch['public_key_base64'], true);
        $signature = base64_decode($signatureBase64, true);
        if ($publicKey === false || $signature === false) {
            return false;
        }

        $message = 'dcg1:continuity:' . $domain . ':' . $challengeToken;
        $valid = sodium_crypto_sign_verify_detached($signature, $message, $publicKey);

        if (!$valid) {
            $this->markContinuityFailed($domain);
            return false;
        }

        if (!$this->consumeChallenge($domain, 'continuity_proof', $challengeToken)) {
            return false;
        }

        $stmt = $this->pdo->prepare(
            'UPDATE dcg_domain_epochs SET last_continuity_check_at=UTC_TIMESTAMP() WHERE id=?'
        );
        $stmt->execute([(int)$epoch['id']]);

        return true;
    }

    public function signContinuityChallenge(string $domain, string $challengeToken, string $privateKeyBase64): string
    {
        $domain = $this->normalizeDomain($domain);
        $privateKey = base64_decode($privateKeyBase64, true);
        if ($privateKey === false || strlen($privateKey) !== SODIUM_CRYPTO_SIGN_SECRETKEYBYTES) {
            throw new RuntimeException('Invalid private key.');
        }

        $message = 'dcg1:continuity:' . $domain . ':' . $challengeToken;
        return base64_encode(sodium_crypto_sign_detached($message, $privateKey));
    }

    public function bindAccountToCurrentDomainEpoch(string $externalAccountId, string $email): array
    {
        $domain = $this->domainFromEmail($email);
        $epoch = $this->getCurrentEpoch($domain);
        if ($epoch === null) {
            throw new RuntimeException('Domain has not been verified with Domain Continuity Guard.');
        }

        $stmt = $this->pdo->prepare(
            'INSERT INTO dcg_account_bindings (external_account_id, email, domain, domain_epoch)
             VALUES (?, ?, ?, ?)
             ON DUPLICATE KEY UPDATE email=VALUES(email), domain=VALUES(domain), domain_epoch=VALUES(domain_epoch)'
        );
        $stmt->execute([$externalAccountId, strtolower(trim($email)), $domain, (int)$epoch['epoch']]);

        return [
            'external_account_id' => $externalAccountId,
            'email' => strtolower(trim($email)),
            'domain' => $domain,
            'domain_epoch' => (int)$epoch['epoch'],
        ];
    }

    public function canRecoverAccountByEmail(string $externalAccountId, string $email): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM dcg_account_bindings WHERE external_account_id=? LIMIT 1');
        $stmt->execute([$externalAccountId]);
        $binding = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$binding) {
            return ['allowed' => false, 'reason' => 'no_domain_epoch_binding'];
        }

        $domain = $this->domainFromEmail($email);
        $currentEpoch = $this->getCurrentEpoch($domain);
        if ($currentEpoch === null) {
            return ['allowed' => false, 'reason' => 'domain_not_verified'];
        }

        if ($domain !== $binding['domain']) {
            return ['allowed' => false, 'reason' => 'email_domain_mismatch'];
        }

        if ((int)$currentEpoch['epoch'] !== (int)$binding['domain_epoch']) {
            return [
                'allowed' => false,
                'reason' => 'domain_epoch_mismatch_possible_new_owner',
                'required' => 'passkey_or_recovery_code_or_old_continuity_key',
            ];
        }

        return ['allowed' => true, 'reason' => 'same_domain_epoch'];
    }

    private function getOrCreateDomainId(string $domain): int
    {
        $stmt = $this->pdo->prepare('SELECT id FROM dcg_domains WHERE domain=? FOR UPDATE');
        $stmt->execute([$domain]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($row) {
            return (int)$row['id'];
        }

        $stmt = $this->pdo->prepare('INSERT INTO dcg_domains (domain) VALUES (?)');
        $stmt->execute([$domain]);
        return (int)$this->pdo->lastInsertId();
    }

    private function getCurrentEpochRowForUpdate(int $domainId): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT * FROM dcg_domain_epochs WHERE domain_id=? AND status="active" ORDER BY epoch DESC LIMIT 1 FOR UPDATE'
        );
        $stmt->execute([$domainId]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    private function getCurrentEpoch(string $domain): ?array
    {
        $stmt = $this->pdo->prepare(
            'SELECT e.* FROM dcg_domain_epochs e JOIN dcg_domains d ON d.id=e.domain_id
             WHERE d.domain=? AND e.status="active" ORDER BY e.epoch DESC LIMIT 1'
        );
        $stmt->execute([$domain]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);
        return $row ?: null;
    }

    private function consumeChallenge(string $domain, string $purpose, string $token): bool
    {
        $tokenHash = hash_hmac('sha256', $token, $this->appSecret);
        $stmt = $this->pdo->prepare(
            'UPDATE dcg_challenges
             SET consumed_at=UTC_TIMESTAMP()
             WHERE domain=? AND purpose=? AND token_hash=? AND consumed_at IS NULL AND expires_at > UTC_TIMESTAMP()'
        );
        $stmt->execute([$domain, $purpose, $tokenHash]);
        return $stmt->rowCount() === 1;
    }

    private function markContinuityFailed(string $domain): void
    {
        $stmt = $this->pdo->prepare('UPDATE dcg_domains SET status="continuity_failed" WHERE domain=?');
        $stmt->execute([$domain]);
    }

    private function domainFromEmail(string $email): string
    {
        $email = strtolower(trim($email));
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new RuntimeException('Invalid email address.');
        }
        return $this->normalizeDomain(substr(strrchr($email, '@'), 1));
    }

    private function base64url(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }
}
