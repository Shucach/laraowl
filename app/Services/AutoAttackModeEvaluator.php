<?php

namespace App\Services;

use App\Models\AttackModeEvent;
use App\Models\Project;
use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;

/**
 * Decides, once per scheduler run, whether a project's Under Attack Mode
 * should be switched on or off based on its traffic signals.
 */
class AutoAttackModeEvaluator
{
    public const OUTCOME_SKIPPED = 'skipped';

    public const OUTCOME_IDLE = 'idle';

    public const OUTCOME_HOLDING = 'holding';

    public const OUTCOME_ENABLED = 'enabled';

    public const OUTCOME_DISABLED = 'disabled';

    public const OUTCOME_SUPPRESSED = 'suppressed';

    public const OUTCOME_MANUAL_OVERRIDE = 'manual_override';

    public const OUTCOME_FAILED = 'failed';

    /**
     * The WAF criterion is critical and may bypass the re-enable cooldown.
     */
    public const CRITERION_WAF_EVENTS = 'waf_events';

    public const CRITERION_TRAFFIC_SPIKE = 'traffic_spike';

    public const CRITERION_FIREWALL_SPIKE = 'firewall_spike';

    public function __construct(
        protected CloudflareService $cloudflareService,
        protected AttackModeService $attackModeService,
        protected AttackModeMetrics $metrics,
    ) {}

    public function evaluate(Project $project, ?CarbonInterface $now = null): string
    {
        $now ??= now();
        $config = $this->attackModeService->config($project);

        if (! $config['enabled'] || ! $this->cloudflareService->isConfigured($project)) {
            return self::OUTCOME_SKIPPED;
        }

        $level = $this->cloudflareService->getSecurityLevel($project);

        if ($level === null) {
            $this->attackModeService->fail($project, AttackModeEvent::SOURCE_AUTOMATIC, 'Cloudflare API unavailable: could not read the current security level.');

            return self::OUTCOME_FAILED;
        }

        $isActive = $level === AttackModeService::UNDER_ATTACK;

        if ($isActive !== $this->attackModeService->state($project)['attack_mode']) {
            $this->attackModeService->adoptExternalChange($project, $isActive);
        }

        $snapshot = $this->metrics->snapshot($project, $config, $now);

        if ($snapshot === null) {
            $this->attackModeService->fail($project, AttackModeEvent::SOURCE_AUTOMATIC, 'Telemetry unavailable: Cloudflare analytics or Laraowl metrics could not be read.');

            return self::OUTCOME_FAILED;
        }

        return $isActive
            ? $this->evaluateDisable($project, $config, $snapshot, $now)
            : $this->evaluateEnable($project, $config, $snapshot, $now);
    }

    /**
     * @param  array<string, bool|int|float>  $config
     * @param  array<string, mixed>  $snapshot
     */
    protected function evaluateEnable(Project $project, array $config, array $snapshot, CarbonInterface $now): string
    {
        $state = $this->attackModeService->state($project);
        $metrics = $this->summary($snapshot);

        $this->attackModeService->touch($project, [
            'last_evaluated_at' => $now->toIso8601String(),
            'quiet_since' => null,
            'last_error' => null,
        ]);

        $trigger = $this->enableTrigger($config, $snapshot);

        if ($trigger === null) {
            return self::OUTCOME_IDLE;
        }

        $sinceManualDisable = $this->attackModeService->minutesSince($state['manual_disabled_at'], $now);

        if ($sinceManualDisable !== null && $sinceManualDisable < $config['manual_cooldown_minutes']) {
            $this->attackModeService->suppress($project, "{$trigger['label']} detected, but attack mode was disabled manually less than {$config['manual_cooldown_minutes']} minutes ago.", $metrics);

            return self::OUTCOME_SUPPRESSED;
        }

        $sinceAutoDisable = $this->attackModeService->minutesSince($state['auto_disabled_at'], $now);

        if ($trigger['criterion'] !== self::CRITERION_WAF_EVENTS
            && $sinceAutoDisable !== null
            && $sinceAutoDisable < $config['reenable_cooldown_minutes']) {
            $this->attackModeService->suppress($project, "{$trigger['label']} detected, but attack mode was disabled automatically less than {$config['reenable_cooldown_minutes']} minutes ago.", $metrics);

            return self::OUTCOME_SUPPRESSED;
        }

        return $this->attackModeService->change($project, true, AttackModeEvent::SOURCE_AUTOMATIC, $trigger['reason'], $metrics)
            ? self::OUTCOME_ENABLED
            : self::OUTCOME_FAILED;
    }

    /**
     * @param  array<string, bool|int|float>  $config
     * @param  array<string, mixed>  $snapshot
     */
    protected function evaluateDisable(Project $project, array $config, array $snapshot, CarbonInterface $now): string
    {
        $state = $this->attackModeService->state($project);
        $metrics = $this->summary($snapshot);
        $quietSince = $this->quietSince($config, $snapshot);
        $quietWindow = (int) $config['quiet_window_minutes'];
        $isQuiet = $quietSince !== null
            && Carbon::parse($quietSince)->diffInMinutes($now->copy()->startOfMinute(), true) >= $quietWindow;

        $this->attackModeService->touch($project, [
            'last_evaluated_at' => $now->toIso8601String(),
            'quiet_since' => $quietSince,
            'last_error' => null,
        ]);

        if ($state['source'] !== AttackModeEvent::SOURCE_AUTOMATIC) {
            if ($isQuiet) {
                $this->attackModeService->suppress($project, 'Traffic is quiet, but attack mode was enabled manually and is never disabled by automation.', $metrics);
            }

            return self::OUTCOME_MANUAL_OVERRIDE;
        }

        $activeMinutes = $this->attackModeService->minutesSince($state['changed_at'], $now);

        if (! $isQuiet || ($activeMinutes !== null && $activeMinutes < $config['min_active_minutes'])) {
            return self::OUTCOME_HOLDING;
        }

        return $this->attackModeService->change($project, false, AttackModeEvent::SOURCE_AUTOMATIC, "Traffic has been back to normal for {$quietWindow} consecutive minutes.", $metrics)
            ? self::OUTCOME_DISABLED
            : self::OUTCOME_FAILED;
    }

    /**
     * The first matching enable criterion; the critical WAF criterion is checked first.
     *
     * @param  array<string, bool|int|float>  $config
     * @param  array<string, mixed>  $snapshot
     * @return array{criterion: string, label: string, reason: string}|null
     */
    public function enableTrigger(array $config, array $snapshot): ?array
    {
        if ($snapshot['waf_events'] >= $config['waf_events_threshold']
            && $snapshot['waf_unique_ips'] >= $config['waf_unique_ips_threshold']) {
            return [
                'criterion' => self::CRITERION_WAF_EVENTS,
                'label' => 'WAF attack',
                'reason' => "{$snapshot['waf_events']} high/critical WAF events from {$snapshot['waf_unique_ips']} IPs within {$config['waf_window_minutes']} minutes.",
            ];
        }

        $spikeWindow = max(1, (int) $config['spike_window_minutes']);
        $spikeMinutes = array_slice($snapshot['minutes'], -$spikeWindow, null, true);

        if (count($spikeMinutes) === $spikeWindow) {
            $signals = [];

            foreach ($spikeMinutes as $minute) {
                $signal = $this->spikeSignal($config, $snapshot, $minute);

                if ($signal === null) {
                    $signals = [];

                    break;
                }

                $signals[] = $signal;
            }

            if ($signals !== []) {
                $baseline = $snapshot['baseline_requests'] !== null ? " and {$config['request_rate_multiplier']}x baseline" : '';

                return [
                    'criterion' => self::CRITERION_TRAFFIC_SPIKE,
                    'label' => 'Traffic spike',
                    'reason' => "Request rate above {$config['request_rate_threshold']} req/min{$baseline} for {$spikeWindow} consecutive minutes ("
                        .implode(', ', array_unique($signals)).').',
                ];
            }
        }

        $latest = end($snapshot['minutes']);

        if ($latest !== false
            && $latest['firewall_events'] >= $config['firewall_events_threshold']
            && $latest['firewall_unique_ips'] >= $config['firewall_unique_ips_threshold']) {
            return [
                'criterion' => self::CRITERION_FIREWALL_SPIKE,
                'label' => 'Cloudflare firewall spike',
                'reason' => "{$latest['firewall_events']} Cloudflare block/challenge events from {$latest['firewall_unique_ips']} IPs in one minute.",
            ];
        }

        return null;
    }

    /**
     * The supporting signal of a spiking minute, or null when the minute is not an attack.
     *
     * @param  array<string, bool|int|float>  $config
     * @param  array<string, mixed>  $snapshot
     * @param  array<string, int|float>  $minute
     */
    protected function spikeSignal(array $config, array $snapshot, array $minute): ?string
    {
        if ($minute['requests'] <= $config['request_rate_threshold']) {
            return null;
        }

        if ($snapshot['baseline_requests'] !== null
            && $minute['requests'] <= $snapshot['baseline_requests'] * $config['request_rate_multiplier']) {
            return null;
        }

        return match (true) {
            $minute['threat_ratio'] >= $config['threat_ratio_threshold'] => 'threat ratio',
            $minute['error_rate'] >= $config['error_rate_threshold'] => '5xx rate',
            $snapshot['baseline_unique_ips'] !== null
                && $snapshot['baseline_unique_ips'] > 0
                && $minute['unique_ips'] >= $snapshot['baseline_unique_ips'] * $config['unique_ip_multiplier'] => 'unique IPs',
            default => null,
        };
    }

    /**
     * Start of the current run of quiet minutes, or null when the latest minute is not quiet.
     *
     * Any new high/critical WAF event inside the quiet window breaks the run.
     *
     * @param  array<string, bool|int|float>  $config
     * @param  array<string, mixed>  $snapshot
     */
    public function quietSince(array $config, array $snapshot): ?string
    {
        if ($snapshot['quiet_waf_events'] > 0) {
            return null;
        }

        $requestLimit = $snapshot['baseline_requests'] !== null
            ? $snapshot['baseline_requests'] * $config['quiet_request_multiplier']
            : $config['quiet_request_rate_threshold'];

        $since = null;

        foreach (array_reverse($snapshot['minutes'], true) as $key => $minute) {
            $isQuiet = $minute['requests'] < $requestLimit
                && $minute['threat_ratio'] < $config['quiet_threat_ratio_threshold']
                && $minute['error_rate'] < $config['quiet_error_rate_threshold'];

            if (! $isQuiet) {
                break;
            }

            $since = $key;
        }

        return $since !== null
            ? Carbon::createFromFormat('Y-m-d H:i', $since, config('app.timezone'))->startOfMinute()->toIso8601String()
            : null;
    }

    /**
     * Latest-minute metrics recorded with transitions and notifications.
     *
     * @param  array<string, mixed>  $snapshot
     * @return array<string, int|float|string|null>
     */
    protected function summary(array $snapshot): array
    {
        $latestKey = array_key_last($snapshot['minutes']);
        $latest = $snapshot['minutes'][$latestKey] ?? [];

        return [
            'minute' => $latestKey,
            'requests_per_minute' => $latest['requests'] ?? 0,
            'baseline_requests' => $snapshot['baseline_requests'],
            'threat_ratio' => $latest['threat_ratio'] ?? 0,
            'error_rate' => $latest['error_rate'] ?? 0,
            'unique_ips' => $latest['unique_ips'] ?? 0,
            'baseline_unique_ips' => $snapshot['baseline_unique_ips'],
            'waf_events' => $snapshot['waf_events'],
            'waf_unique_ips' => $snapshot['waf_unique_ips'],
            'firewall_events' => $latest['firewall_events'] ?? 0,
            'firewall_unique_ips' => $latest['firewall_unique_ips'] ?? 0,
        ];
    }
}
