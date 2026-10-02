<?php

namespace App\Services;

use App\Models\Project;
use App\Models\Record;
use App\Models\RecordRollup;
use Carbon\CarbonInterface;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Log;
use Throwable;

/**
 * Collects the per-minute signals Auto Attack Mode decides on.
 *
 * Request volume comes from Cloudflare's edge analytics, which are complete
 * regardless of the Laraowl client's sampling. Laraowl telemetry is only used
 * for ratios and relative values (5xx share, unique IPs against their own
 * baseline) and for WAF events, which sampling does not distort in a way that
 * matters for the thresholds.
 *
 * The threat ratio and firewall spikes only count what Cloudflare mitigated
 * beyond the zone's usual volume, so rules that block bots or countries around
 * the clock do not read as an attack.
 */
class AttackModeMetrics
{
    /**
     * Hours of history used to build a baseline.
     */
    public const BASELINE_HOURS = 24;

    /**
     * Most recent minutes left out of the baseline so an ongoing attack does not inflate it.
     */
    public const BASELINE_EXCLUDED_MINUTES = 15;

    /**
     * Minutes of history needed before a baseline is trusted.
     */
    public const MIN_BASELINE_MINUTES = 60;

    /**
     * How long a computed baseline is reused.
     */
    public const BASELINE_CACHE_SECONDS = 300;

    /**
     * Most recent completed minutes left out of the snapshot, as Cloudflare's analytics still fill them in.
     */
    public const ANALYTICS_DELAY_MINUTES = 3;

    /**
     * Multiple of the median mitigated requests per minute still treated as the zone's usual volume.
     */
    public const MITIGATION_TOLERANCE = 1.5;

    public function __construct(protected CloudflareService $cloudflareService) {}

    /**
     * Snapshot of the minutes Cloudflare has completed analytics for, or null when Cloudflare or telemetry is unavailable.
     *
     * The window ends ANALYTICS_DELAY_MINUTES before the current minute; WAF
     * events are Laraowl's own and are counted up to $now.
     *
     * @param  array<string, bool|int|float>  $config
     * @return array{minutes: array<string, array{requests: int, mitigated: int, threat_ratio: float, error_rate: float, unique_ips: int, firewall_events: int, firewall_unique_ips: int}>, until: string, baseline_requests: float|null, baseline_mitigated: float|null, usual_mitigated: float, baseline_unique_ips: float|null, waf_events: int, waf_unique_ips: int, quiet_waf_events: int}|null
     */
    public function snapshot(Project $project, array $config, CarbonInterface $now): ?array
    {
        $until = $now->copy()->startOfMinute()->subMinutes(self::ANALYTICS_DELAY_MINUTES);
        $windowMinutes = max((int) $config['spike_window_minutes'], (int) $config['quiet_window_minutes'], 1);
        $since = $until->copy()->subMinutes($windowMinutes);

        $traffic = $this->cloudflareService->getMinuteTraffic($project, $since, $until);
        $baseline = $this->baseline($project, $until);

        if ($traffic === null || $baseline === null) {
            return null;
        }

        try {
            $errorRates = $this->errorRates($project, $since, $until);
            $uniqueIps = $this->uniqueIpsPerMinute($project, $since, $until);
            $waf = $this->wafEvents($project, $now->copy()->subMinutes((int) $config['waf_window_minutes']));
            $quietWaf = $this->wafEvents($project, $now->copy()->subMinutes((int) $config['quiet_window_minutes']));
        } catch (Throwable $e) {
            Log::error('Attack mode telemetry unavailable: '.$e->getMessage());

            return null;
        }

        $usualMitigated = ($baseline['mitigated'] ?? 0) * self::MITIGATION_TOLERANCE;
        $minutes = [];

        for ($minute = $since->toImmutable(); $minute->lt($until); $minute = $minute->addMinute()) {
            $key = $minute->format('Y-m-d H:i');
            $requests = $traffic['requests'][$key] ?? 0;
            $mitigated = $traffic['mitigated'][$key] ?? 0;
            $firewall = $traffic['firewall'][$key] ?? ['count' => 0, 'ips' => []];

            $minutes[$key] = [
                'requests' => $requests,
                'mitigated' => $mitigated,
                'threat_ratio' => $this->percentage(max(0, $mitigated - $usualMitigated), max($requests, $mitigated)),
                'error_rate' => $errorRates[$key] ?? 0.0,
                'unique_ips' => $uniqueIps[$key] ?? 0,
                'firewall_events' => $firewall['count'],
                'firewall_unique_ips' => count($firewall['ips']),
            ];
        }

        return [
            'minutes' => $minutes,
            'until' => $until->toIso8601String(),
            'baseline_requests' => $baseline['requests'],
            'baseline_mitigated' => $baseline['mitigated'] ?? null,
            'usual_mitigated' => $usualMitigated,
            'baseline_unique_ips' => $baseline['unique_ips'],
            'waf_events' => $waf['events'],
            'waf_unique_ips' => $waf['ips'],
            'quiet_waf_events' => $quietWaf['events'],
        ];
    }

    /**
     * Median requests, mitigated requests and unique IPs per minute over the
     * last day, excluding the most recent minutes. A metric without enough
     * history is null.
     *
     * @return array{requests: float|null, mitigated: float|null, unique_ips: float|null}|null
     */
    public function baseline(Project $project, CarbonInterface $until): ?array
    {
        $cacheKey = "attack_mode_baseline_{$project->id}";

        if (($cached = Cache::get($cacheKey)) !== null) {
            return $cached;
        }

        $baselineUntil = $until->copy()->subMinutes(self::BASELINE_EXCLUDED_MINUTES);
        $baselineSince = $until->copy()->subHours(self::BASELINE_HOURS);

        $counts = $this->cloudflareService->getMinuteRequests($project, $baselineSince, $baselineUntil);

        if ($counts === null) {
            return null;
        }

        try {
            $uniqueIps = $this->uniqueIpsPerMinute($project, $baselineSince, $baselineUntil);
        } catch (Throwable $e) {
            Log::error('Attack mode baseline telemetry unavailable: '.$e->getMessage());

            return null;
        }

        $baseline = [
            'requests' => $this->median($counts['requests']),
            // Minutes without a mitigated request are missing from the response
            'mitigated' => $this->median(array_map(fn (string $minute) => $counts['mitigated'][$minute] ?? 0, array_keys($counts['requests']))),
            'unique_ips' => $this->median($uniqueIps),
        ];

        Cache::put($cacheKey, $baseline, self::BASELINE_CACHE_SECONDS);

        return $baseline;
    }

    /**
     * HTTP 5xx share per minute, in percent.
     *
     * @return array<string, float>
     */
    protected function errorRates(Project $project, CarbonInterface $since, CarbonInterface $until): array
    {
        return RecordRollup::query()
            ->where('project_id', $project->id)
            ->where('type', 'request')
            ->where('bucket', '>=', $since)
            ->where('bucket', '<', $until)
            ->get(['bucket', 'count', 'server_error_count'])
            ->mapWithKeys(fn (RecordRollup $rollup) => [
                $rollup->bucket->format('Y-m-d H:i') => $this->percentage((int) $rollup->server_error_count, (int) $rollup->count),
            ])
            ->all();
    }

    /**
     * Distinct client IPs per minute seen in request telemetry.
     *
     * @return array<string, int>
     */
    protected function uniqueIpsPerMinute(Project $project, CarbonInterface $since, CarbonInterface $until): array
    {
        $minute = $this->minuteExpression('created_at');

        return Record::query()
            ->where('project_id', $project->id)
            ->where('type', 'request')
            ->where('created_at', '>=', $since)
            ->where('created_at', '<', $until)
            ->whereNotNull('ip')
            ->selectRaw("{$minute} as minute, count(distinct ip) as ips")
            ->groupByRaw($minute)
            ->toBase()
            ->get()
            ->mapWithKeys(fn (object $row) => [$row->minute => (int) $row->ips])
            ->all();
    }

    /**
     * High and critical risk WAF events recorded by Laraowl since the given time.
     *
     * @return array{events: int, ips: int}
     */
    protected function wafEvents(Project $project, CarbonInterface $since): array
    {
        $row = Record::query()
            ->join('issues', 'issues.id', '=', 'records.issue_id')
            ->where('records.project_id', $project->id)
            ->where('records.type', 'request')
            ->where('records.created_at', '>=', $since)
            ->where('issues.type', 'security')
            ->whereIn('issues.priority', ['high', 'critical'])
            ->selectRaw('count(*) as events, count(distinct records.ip) as ips')
            ->toBase()
            ->first();

        return ['events' => (int) ($row->events ?? 0), 'ips' => (int) ($row->ips ?? 0)];
    }

    /**
     * SQL that floors a timestamp column to a 'Y-m-d H:i' minute key.
     */
    protected function minuteExpression(string $column): string
    {
        return match (DB::connection()->getDriverName()) {
            'pgsql' => "to_char({$column}, 'YYYY-MM-DD HH24:MI')",
            'mysql', 'mariadb' => "DATE_FORMAT({$column}, '%Y-%m-%d %H:%i')",
            default => "strftime('%Y-%m-%d %H:%M', {$column})",
        };
    }

    /**
     * Median of the per-minute values, or null without enough minutes of history.
     *
     * @param  array<string, int|float>  $values
     */
    protected function median(array $values): ?float
    {
        if (count($values) < self::MIN_BASELINE_MINUTES) {
            return null;
        }

        $sorted = array_values($values);
        sort($sorted);
        $middle = intdiv(count($sorted), 2);

        return count($sorted) % 2 === 0
            ? ($sorted[$middle - 1] + $sorted[$middle]) / 2
            : (float) $sorted[$middle];
    }

    protected function percentage(int|float $part, int $total): float
    {
        return $total > 0 ? round($part / $total * 100, 2) : 0.0;
    }
}
