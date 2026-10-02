<?php

namespace App\Services;

use App\Models\AttackModeEvent;
use App\Models\Project;
use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;

/**
 * Owns the attack mode state of a project: every change, whether manual or
 * automatic, goes through here so Cloudflare, the local state and the audit
 * log never drift apart.
 */
class AttackModeService
{
    public const UNDER_ATTACK = 'under_attack';

    public const DEFAULT_LEVEL = 'high';

    /**
     * Default Auto Attack Mode configuration, stored per project under settings.auto_attack_mode.
     *
     * Percentages are whole numbers (10 = 10%), windows are minutes.
     *
     * @var array<string, bool|int|float>
     */
    public const DEFAULTS = [
        'enabled' => false,
        'request_rate_threshold' => 300,
        'request_rate_multiplier' => 3,
        'spike_window_minutes' => 3,
        'threat_ratio_threshold' => 10,
        'error_rate_threshold' => 10,
        'unique_ip_multiplier' => 3,
        'waf_events_threshold' => 20,
        'waf_unique_ips_threshold' => 5,
        'waf_window_minutes' => 2,
        'firewall_events_threshold' => 100,
        'firewall_unique_ips_threshold' => 10,
        'min_active_minutes' => 10,
        'quiet_window_minutes' => 15,
        'quiet_request_multiplier' => 1.5,
        'quiet_request_rate_threshold' => 150,
        'quiet_threat_ratio_threshold' => 2,
        'quiet_error_rate_threshold' => 3,
        'manual_cooldown_minutes' => 30,
        'reenable_cooldown_minutes' => 10,
    ];

    public function __construct(
        protected CloudflareService $cloudflareService,
        protected AlertService $alertService,
    ) {}

    /**
     * The project's Auto Attack Mode configuration merged over the defaults.
     *
     * @return array<string, bool|int|float>
     */
    public function config(Project $project): array
    {
        return array_merge(self::DEFAULTS, $project->settings['auto_attack_mode'] ?? []);
    }

    /**
     * The locally stored attack mode state.
     *
     * @return array{attack_mode: bool, source: string|null, changed_at: string|null, reason: string|null, metrics: array<string, mixed>|null, manual_disabled_at: string|null, auto_disabled_at: string|null, last_evaluated_at: string|null, quiet_since: string|null, last_error: string|null}
     */
    public function state(Project $project): array
    {
        $firewall = $project->settings['firewall_settings'] ?? [];

        return array_merge([
            'source' => null,
            'changed_at' => null,
            'reason' => null,
            'metrics' => null,
            'manual_disabled_at' => null,
            'auto_disabled_at' => null,
            'last_evaluated_at' => null,
            'quiet_since' => null,
            'last_error' => null,
        ], $firewall['attack_mode_state'] ?? [], [
            'attack_mode' => (bool) ($firewall['attack_mode'] ?? false),
        ]);
    }

    /**
     * Switch attack mode on Cloudflare, confirm it and persist the result.
     *
     * The local state is only written once Cloudflare reports the requested
     * security level back, so a failed or partial change never leaves the two
     * out of sync.
     *
     * @param  array<string, mixed>|null  $metrics
     */
    public function change(Project $project, bool $enabled, string $source, string $reason, ?array $metrics = null): bool
    {
        $expected = $enabled ? self::UNDER_ATTACK : self::DEFAULT_LEVEL;

        if (! $this->cloudflareService->toggleAttackMode($project, $enabled)) {
            $this->fail($project, $source, $this->cloudflareService->lastError() ?? 'Cloudflare rejected the security level change.', $metrics);

            return false;
        }

        $actual = $this->cloudflareService->getSecurityLevel($project);

        if ($actual !== $expected) {
            if ($actual !== null) {
                $this->syncLocal($project, $actual === self::UNDER_ATTACK);
            }

            $this->fail($project, $source, $actual === null
                ? 'Could not confirm the security level on Cloudflare. '.$this->cloudflareService->lastError()
                : "Cloudflare reports security level '{$actual}' instead of '{$expected}'.", $metrics);

            return false;
        }

        $now = now();

        $this->updateState($project, $enabled, array_filter([
            'source' => $source,
            'changed_at' => $now->toIso8601String(),
            'reason' => $reason,
            'metrics' => $metrics,
            'quiet_since' => null,
            'last_error' => null,
            'manual_disabled_at' => ! $enabled && $source === AttackModeEvent::SOURCE_MANUAL ? $now->toIso8601String() : false,
            'auto_disabled_at' => ! $enabled && $source === AttackModeEvent::SOURCE_AUTOMATIC ? $now->toIso8601String() : false,
        ], fn ($value) => $value !== false));

        $this->audit($project, $enabled ? AttackModeEvent::ACTION_ENABLED : AttackModeEvent::ACTION_DISABLED, $source, $reason, $metrics);

        if ($source === AttackModeEvent::SOURCE_AUTOMATIC) {
            $this->alertService->notifyAttackModeChanged($project, $enabled, $reason, $metrics ?? [], $now);
        }

        return true;
    }

    /**
     * Adopt a security level that was changed outside Laraowl (e.g. the Cloudflare dashboard).
     *
     * An external change is treated as manual: an enabled mode is never
     * disabled by automation and a disabled one starts the manual cooldown.
     */
    public function adoptExternalChange(Project $project, bool $enabled): void
    {
        $now = now()->toIso8601String();
        $reason = 'Security level changed outside Laraowl.';

        $this->updateState($project, $enabled, array_filter([
            'source' => AttackModeEvent::SOURCE_MANUAL,
            'changed_at' => $now,
            'reason' => $reason,
            'metrics' => null,
            'quiet_since' => null,
            'manual_disabled_at' => $enabled ? false : $now,
        ], fn ($value) => $value !== false));

        $this->audit($project, $enabled ? AttackModeEvent::ACTION_ENABLED : AttackModeEvent::ACTION_DISABLED, AttackModeEvent::SOURCE_MANUAL, $reason);
    }

    /**
     * Record a failed attempt and alert the project's integrations.
     *
     * @param  array<string, mixed>|null  $metrics
     */
    public function fail(Project $project, string $source, string $error, ?array $metrics = null): void
    {
        $this->updateState($project, null, ['last_error' => $error]);

        // A persistent outage is audited once rather than on every scheduler run
        if ($source === AttackModeEvent::SOURCE_MANUAL || ! $this->repeatsLatestEvent($project, AttackModeEvent::ACTION_FAILED, $error)) {
            $this->audit($project, AttackModeEvent::ACTION_FAILED, $source, $error, $metrics);
        }

        $this->alertService->notifyAttackModeFailed($project, $error);
    }

    /**
     * Record a transition that was held back, once per distinct reason in a row.
     *
     * @param  array<string, mixed>|null  $metrics
     */
    public function suppress(Project $project, string $reason, ?array $metrics = null): void
    {
        if ($this->repeatsLatestEvent($project, AttackModeEvent::ACTION_SUPPRESSED, $reason)) {
            return;
        }

        $this->audit($project, AttackModeEvent::ACTION_SUPPRESSED, AttackModeEvent::SOURCE_AUTOMATIC, $reason, $metrics);
    }

    protected function repeatsLatestEvent(Project $project, string $action, string $reason): bool
    {
        $latest = $project->attackModeEvents()->latest('created_at')->latest('id')->first();

        return $latest?->action === $action && $latest->reason === mb_substr($reason, 0, 255);
    }

    /**
     * Merge automation bookkeeping into the stored state.
     *
     * @param  array<string, mixed>  $values
     */
    public function touch(Project $project, array $values): void
    {
        $this->updateState($project, null, $values);
    }

    /**
     * Mirror a known Cloudflare state locally without recording a transition.
     */
    public function syncLocal(Project $project, bool $enabled): void
    {
        $this->updateState($project, $enabled, []);
    }

    /**
     * Minutes elapsed since an ISO timestamp stored in the state, or null when unset.
     */
    public function minutesSince(?string $timestamp, CarbonInterface $now): ?float
    {
        return $timestamp ? Carbon::parse($timestamp)->diffInSeconds($now, true) / 60 : null;
    }

    /**
     * @param  array<string, mixed>|null  $metrics
     */
    protected function audit(Project $project, string $action, string $source, ?string $reason, ?array $metrics = null): void
    {
        $project->attackModeEvents()->create([
            'action' => $action,
            'source' => $source,
            'reason' => $reason !== null ? mb_substr($reason, 0, 255) : null,
            'metrics' => $metrics,
            'created_at' => now(),
        ]);
    }

    /**
     * Write the attack mode flag and state on a fresh copy of the settings,
     * so concurrent edits to other settings keys are not overwritten.
     *
     * @param  array<string, mixed>  $state
     */
    protected function updateState(Project $project, ?bool $enabled, array $state): void
    {
        $project->refresh();

        $settings = $project->settings ?? [];
        $firewall = $settings['firewall_settings'] ?? [];

        if ($enabled !== null) {
            $firewall['attack_mode'] = $enabled;
        }

        $firewall['attack_mode_state'] = array_merge($firewall['attack_mode_state'] ?? [], $state);
        $settings['firewall_settings'] = $firewall;

        $project->update(['settings' => $settings]);
    }
}
