<?php

namespace App\Services;

use App\Models\Project;
use Carbon\CarbonInterface;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class CloudflareService
{
    /**
     * Firewall actions counted as a mitigation (block or challenge).
     */
    public const MITIGATION_ACTIONS = ['block', 'challenge', 'jschallenge', 'managed_challenge'];

    /**
     * The error message of the last failed attack mode toggle.
     */
    protected ?string $lastError = null;

    public function lastError(): ?string
    {
        return $this->lastError;
    }

    public function isConfigured(Project $project): bool
    {
        $settings = $project->settings['cloudflare'] ?? [];

        return ! empty($settings['api_token']) && ! empty($settings['zone_id']);
    }

    /**
     * Get the connection status without exposing the API token.
     *
     * @return array{connected: bool, zone_id: string|null, token_hint: string|null, connected_at: string|null}
     */
    public function connectionSummary(Project $project): array
    {
        if (! $this->isConfigured($project)) {
            return [
                'connected' => false,
                'zone_id' => null,
                'token_hint' => null,
                'connected_at' => null,
            ];
        }

        $settings = $project->settings['cloudflare'];

        return [
            'connected' => true,
            'zone_id' => $settings['zone_id'],
            'token_hint' => substr($settings['api_token'], -4),
            'connected_at' => $settings['connected_at'] ?? null,
        ];
    }

    public function checkHealth(Project $project): bool
    {
        if (! $this->isConfigured($project)) {
            return false;
        }

        $settings = $project->settings['cloudflare'];

        return $this->verifyConnection($settings['api_token'], $settings['zone_id']);
    }

    /**
     * Verify Cloudflare connection.
     */
    public function verifyConnection(string $token, string $zoneId): bool
    {
        try {
            $response = Http::withToken($token)
                ->get("https://api.cloudflare.com/client/v4/zones/$zoneId");

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Cloudflare Verification Failed: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Get traffic analytics from Cloudflare.
     */
    public function getTrafficAnalytics(Project $project, string $period = '24h'): array
    {
        $settings = $project->settings['cloudflare'] ?? [];
        $token = $settings['api_token'] ?? null;
        $zoneId = $settings['zone_id'] ?? null;

        if (! $token || ! $zoneId) {
            return ['data' => ['viewer' => ['zones' => []]]];
        }

        try {
            $response = Http::withToken($token)
                ->post('https://api.cloudflare.com/client/v4/graphql', [
                    'query' => $this->getAnalyticsQuery($zoneId, $period),
                ]);

            if ($response->successful()) {
                $json = $response->json();

                if (isset($json['errors']) && ! empty($json['errors'])) {
                    Log::error('Cloudflare GraphQL Errors: '.json_encode($json['errors']));
                }

                return $json;
            } else {
                Log::error('Cloudflare API HTTP Error: '.$response->status().' - '.$response->body());
            }
        } catch (\Exception $e) {
            Log::error('Cloudflare API Exception: '.$e->getMessage());
        }

        return ['data' => ['viewer' => ['zones' => []]]];
    }

    /**
     * Update Firewall rules on Cloudflare.
     */
    public function updateFirewallRule(Project $project, string $ruleId, array $data): bool
    {
        $settings = $project->settings['cloudflare'] ?? [];
        $token = $settings['api_token'] ?? null;
        $zoneId = $settings['zone_id'] ?? null;

        if (! $token || ! $zoneId) {
            return false;
        }

        try {
            $response = Http::withToken($token)
                ->patch("https://api.cloudflare.com/client/v4/zones/$zoneId/firewall/rules/$ruleId", $data);

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Cloudflare Rule Update Error: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Create an IP Access Rule (Block/Whitelist)
     */
    public function createIpAccessRule(Project $project, string $ip, string $action = 'block', string $note = ''): array|bool
    {
        $settings = $project->settings['cloudflare'] ?? [];
        $token = $settings['api_token'] ?? null;
        $zoneId = $settings['zone_id'] ?? null;

        if (! $token || ! $zoneId) {
            return false;
        }

        try {
            $response = Http::withToken($token)
                ->post("https://api.cloudflare.com/client/v4/zones/$zoneId/firewall/access_rules/rules", [
                    'mode' => $action,
                    'configuration' => [
                        'target' => 'ip',
                        'value' => $ip,
                    ],
                    'notes' => $note,
                ]);

            if ($response->successful()) {
                return $response->json()['result'];
            }

            Log::error('Cloudflare IP Rule Create Error: '.$response->body());

            return false;
        } catch (\Exception $e) {
            Log::error('Cloudflare IP Rule Exception: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Delete an IP Access Rule
     */
    public function deleteIpAccessRule(Project $project, string $ruleId): bool
    {
        $settings = $project->settings['cloudflare'] ?? [];
        $token = $settings['api_token'] ?? null;
        $zoneId = $settings['zone_id'] ?? null;

        if (! $token || ! $zoneId) {
            return false;
        }

        try {
            $response = Http::withToken($token)
                ->delete("https://api.cloudflare.com/client/v4/zones/$zoneId/firewall/access_rules/rules/$ruleId");

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Cloudflare IP Rule Delete Error: '.$e->getMessage());

            return false;
        }
    }

    /**
     * Update Zone Settings (Bot Management, etc.)
     */
    public function updateZoneSetting(Project $project, string $setting, $value): bool
    {
        $settings = $project->settings['cloudflare'] ?? [];
        $token = $settings['api_token'] ?? null;
        $zoneId = $settings['zone_id'] ?? null;

        if (! $token || ! $zoneId) {
            return false;
        }

        $endpoint = match ($setting) {
            'hotlink_protection' => "https://api.cloudflare.com/client/v4/zones/$zoneId/settings/hotlink_protection",
            'security_level' => "https://api.cloudflare.com/client/v4/zones/$zoneId/settings/security_level",
            'browser_check' => "https://api.cloudflare.com/client/v4/zones/$zoneId/settings/browser_check",
            default => null
        };

        if (! $endpoint) {
            return false;
        }

        try {
            $data = match ($setting) {
                'hotlink_protection' => ['value' => $value ? 'on' : 'off'],
                'security_level' => ['value' => $value],
                'browser_check' => ['value' => $value ? 'on' : 'off'],
                default => []
            };

            $response = Http::withToken($token)->patch($endpoint, $data);

            if (! $response->successful()) {
                $error = $response->json();
                $msg = $error['errors'][0]['message'] ?? 'Unknown Error';
                $code = $error['errors'][0]['code'] ?? 0;

                if ($code == 10405 || $code == 9109 || $code == 10000 || $code == 1006) {
                    Log::warning("Cloudflare Permission/Plan Issue ($setting): $msg (Code: $code). This feature may not be available on your plan.");
                } else {
                    Log::error("Cloudflare Setting Update Failed ($setting): ".$response->body());
                }
            }

            return $response->successful();
        } catch (\Exception $e) {
            Log::error("Cloudflare Setting Update Error ($setting): ".$e->getMessage());

            return false;
        }
    }

    /**
     * Get the zone's current security level, or null when it cannot be read.
     */
    public function getSecurityLevel(Project $project): ?string
    {
        if (! $this->isConfigured($project)) {
            return null;
        }

        $settings = $project->settings['cloudflare'];

        try {
            $response = Http::withToken($settings['api_token'])
                ->get("https://api.cloudflare.com/client/v4/zones/{$settings['zone_id']}/settings/security_level");

            if (! $response->successful()) {
                return null;
            }

            return $response->json('result.value');
        } catch (\Exception $e) {
            Log::error('Cloudflare Security Level Fetch Error: '.$e->getMessage());

            return null;
        }
    }

    /**
     * Toggle Under Attack Mode.
     */
    public function toggleAttackMode(Project $project, bool $enabled): bool
    {
        $settings = $project->settings['cloudflare'] ?? [];
        $token = $settings['api_token'] ?? null;
        $zoneId = $settings['zone_id'] ?? null;
        $this->lastError = null;

        if (! $token || ! $zoneId) {
            $this->lastError = 'Cloudflare is not connected.';

            return false;
        }

        try {
            $response = Http::withToken($token)
                ->patch("https://api.cloudflare.com/client/v4/zones/$zoneId/settings/security_level", [
                    'value' => $enabled ? 'under_attack' : 'high',
                ]);

            if (! $response->successful()) {
                $error = $response->json();
                $msg = $error['errors'][0]['message'] ?? 'Unauthorized/Unknown Error';
                Log::error('Cloudflare Attack Mode Toggle Failed: '.$response->body());
                $this->lastError = "Cloudflare Error: $msg. Please ensure your API Token has 'Zone.Settings: Edit' permission.";
                session()->flash('cloudflare_error', $this->lastError);
            }

            return $response->successful();
        } catch (\Exception $e) {
            Log::error('Cloudflare Attack Mode Error: '.$e->getMessage());
            $this->lastError = 'Cloudflare Error: '.$e->getMessage();

            return false;
        }
    }

    /**
     * Get Firewall Events using GraphQL.
     */
    public function getFirewallEvents(Project $project): array
    {
        $settings = $project->settings['cloudflare'] ?? [];
        $token = $settings['api_token'] ?? null;
        $zoneId = $settings['zone_id'] ?? null;

        if (! $token || ! $zoneId) {
            return [];
        }

        $yesterday = now()->subHours(23)->toIso8601String();
        $query = <<<'GQL'
        query ($zoneTag: string, $datetime_gt: string) {
          viewer {
            zones(filter: { zoneTag: $zoneTag }) {
              firewallEventsAdaptive(
                limit: 100
                filter: { datetime_gt: $datetime_gt }
                orderBy: [datetime_DESC]
              ) {
                action
                clientAsn
                clientCountryName
                clientIP
                clientRequestHTTPHost
                clientRequestHTTPMethodName
                clientRequestHTTPProtocol
                clientRequestPath
                clientRequestQuery
                datetime
                edgeResponseStatus
                kind
                originResponseStatus
                rayName
                ruleId
                source
                userAgent
              }
            }
          }
        }
GQL;

        try {
            $response = Http::withToken($token)
                ->post('https://api.cloudflare.com/client/v4/graphql', [
                    'query' => $query,
                    'variables' => [
                        'zoneTag' => $zoneId,
                        'datetime_gt' => $yesterday,
                    ],
                ]);

            if ($response->successful()) {
                $data = $response->json();

                if (isset($data['errors']) && ! empty($data['errors'])) {
                    Log::error('Cloudflare GraphQL Errors: '.json_encode($data['errors']));

                    return [];
                }

                return $data['data']['viewer']['zones'][0]['firewallEventsAdaptive'] ?? [];
            }

            Log::error('Cloudflare GraphQL Request Failed: '.$response->body());

            return [];
        } catch (\Exception $e) {
            Log::error('Cloudflare GraphQL Exception: '.$e->getMessage());

            return [];
        }
    }

    /**
     * Per-minute edge request counts and block/challenge firewall events.
     *
     * Adaptive group counts are already adjusted for Cloudflare's sampling.
     * Challenges issued by the security level itself (Under Attack Mode) are
     * excluded, otherwise an active mode would keep its own threat ratio high.
     * Returns null when the data cannot be read, so callers can tell an
     * outage apart from a quiet zone.
     *
     * @return array{requests: array<string, int>, firewall: array<string, array{count: int, ips: array<int, string>}>}|null
     */
    public function getMinuteTraffic(Project $project, CarbonInterface $since, CarbonInterface $until): ?array
    {
        $query = <<<'GQL'
        query ($zoneTag: string, $since: Time, $until: Time, $actions: [string!]) {
          viewer {
            zones(filter: { zoneTag: $zoneTag }) {
              requests: httpRequestsAdaptiveGroups(
                limit: 1000
                filter: { datetime_geq: $since, datetime_lt: $until }
                orderBy: [datetimeMinute_ASC]
              ) {
                count
                dimensions { datetimeMinute }
              }
              firewall: firewallEventsAdaptiveGroups(
                limit: 10000
                filter: { datetime_geq: $since, datetime_lt: $until, action_in: $actions, source_neq: "securitylevel" }
                orderBy: [datetimeMinute_ASC]
              ) {
                count
                dimensions { datetimeMinute clientIP }
              }
            }
          }
        }
GQL;

        $zone = $this->graphql($project, $query, [
            'since' => $since->copy()->utc()->toIso8601ZuluString(),
            'until' => $until->copy()->utc()->toIso8601ZuluString(),
            'actions' => self::MITIGATION_ACTIONS,
        ]);

        if ($zone === null) {
            return null;
        }

        $requests = [];
        foreach ($zone['requests'] ?? [] as $group) {
            $minute = $this->minuteKey($group['dimensions']['datetimeMinute']);
            $requests[$minute] = ($requests[$minute] ?? 0) + (int) $group['count'];
        }

        $firewall = [];
        foreach ($zone['firewall'] ?? [] as $group) {
            $minute = $this->minuteKey($group['dimensions']['datetimeMinute']);
            $firewall[$minute] ??= ['count' => 0, 'ips' => []];
            $firewall[$minute]['count'] += (int) $group['count'];
            $firewall[$minute]['ips'][] = (string) ($group['dimensions']['clientIP'] ?? '');
        }

        foreach ($firewall as $minute => $bucket) {
            $firewall[$minute]['ips'] = array_values(array_unique($bucket['ips']));
        }

        return ['requests' => $requests, 'firewall' => $firewall];
    }

    /**
     * Per-minute edge request counts, used to build the traffic baseline.
     *
     * @return array<string, int>|null
     */
    public function getMinuteRequestCounts(Project $project, CarbonInterface $since, CarbonInterface $until): ?array
    {
        $query = <<<'GQL'
        query ($zoneTag: string, $since: Time, $until: Time) {
          viewer {
            zones(filter: { zoneTag: $zoneTag }) {
              requests: httpRequestsAdaptiveGroups(
                limit: 1500
                filter: { datetime_geq: $since, datetime_lt: $until }
                orderBy: [datetimeMinute_ASC]
              ) {
                count
                dimensions { datetimeMinute }
              }
            }
          }
        }
GQL;

        $zone = $this->graphql($project, $query, [
            'since' => $since->copy()->utc()->toIso8601ZuluString(),
            'until' => $until->copy()->utc()->toIso8601ZuluString(),
        ]);

        if ($zone === null) {
            return null;
        }

        $requests = [];
        foreach ($zone['requests'] ?? [] as $group) {
            $minute = $this->minuteKey($group['dimensions']['datetimeMinute']);
            $requests[$minute] = ($requests[$minute] ?? 0) + (int) $group['count'];
        }

        return $requests;
    }

    /**
     * Run a zone-scoped GraphQL query and return the zone node, or null on failure.
     *
     * @param  array<string, mixed>  $variables
     * @return array<string, mixed>|null
     */
    protected function graphql(Project $project, string $query, array $variables): ?array
    {
        if (! $this->isConfigured($project)) {
            return null;
        }

        $settings = $project->settings['cloudflare'];

        try {
            $response = Http::withToken($settings['api_token'])
                ->post('https://api.cloudflare.com/client/v4/graphql', [
                    'query' => $query,
                    'variables' => ['zoneTag' => $settings['zone_id']] + $variables,
                ]);

            if (! $response->successful() || ! empty($response->json('errors'))) {
                Log::error('Cloudflare GraphQL Request Failed: '.$response->body());

                return null;
            }

            return $response->json('data.viewer.zones.0') ?? [];
        } catch (\Exception $e) {
            Log::error('Cloudflare GraphQL Exception: '.$e->getMessage());

            return null;
        }
    }

    /**
     * Normalise a Cloudflare minute timestamp to an app-timezone minute key.
     */
    public function minuteKey(string $datetime): string
    {
        return Carbon::parse($datetime)->setTimezone(config('app.timezone'))->format('Y-m-d H:i');
    }

    protected function getAnalyticsQuery(string $zoneId, string $period): string
    {
        $date = match ($period) {
            '24h' => now()->subDay()->format('Y-m-d'),
            '7d' => now()->subDays(7)->format('Y-m-d'),
            '30d' => now()->subDays(30)->format('Y-m-d'),
            default => now()->subDay()->format('Y-m-d')
        };

        $datetime = match ($period) {
            '24h' => now()->subDay()->toIso8601String(),
            '7d' => now()->subDays(7)->toIso8601String(),
            '30d' => now()->subDays(30)->toIso8601String(),
            default => now()->subDay()->toIso8601String()
        };

        return <<<GQL
        {
          viewer {
            zones(filter: {zoneTag: "$zoneId"}) {
              # General Traffic
              httpRequests1dGroups(limit: 30, filter: {date_gt: "$date"}) {
                sum {
                  requests
                  pageViews
                  threats
                }
                dimensions {
                  date
                }
              }
            }
          }
        }
        GQL;
    }
}
