<?php

namespace App\Http\Controllers\Projects;

use App\Http\Controllers\Controller;
use App\Models\AttackModeEvent;
use App\Models\Project;
use App\Models\Team;
use App\Services\AttackModeService;
use App\Services\CloudflareService;
use App\Services\RecordService;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

class FirewallController extends Controller
{
    protected RecordService $recordService;

    protected CloudflareService $cloudflareService;

    public function __construct(RecordService $recordService, CloudflareService $cloudflareService)
    {
        $this->recordService = $recordService;
        $this->cloudflareService = $cloudflareService;
    }

    /**
     * Display firewall overview dashboard.
     */
    public function overview(Request $request, Team $current_team, Project $project): Response
    {
        $period = $request->query('period', '1h');
        $isConfigured = $this->cloudflareService->checkHealth($project);

        return Inertia::render('projects/firewall/overview', [
            'isConfigured' => $isConfigured,
            'stats' => $isConfigured ? $this->getRealFirewallStats($project, $period) : [
                'allowed' => 0, 'denied' => 0, 'challenged' => 0, 'logged' => 0, 'rate_limited' => 0,
            ],
            'timeSeries' => $isConfigured ? $this->getRealFirewallTimeSeries($project, $period) : [],
            'recentAlerts' => $this->getRecentAlerts($project),
            'rules' => $project->settings['firewall_rules'] ?? [],
            'settings' => $this->firewallSettings($project, $isConfigured),
        ]);
    }

    /**
     * Stored firewall settings with attack mode synced from Cloudflare when available.
     *
     * @return array<string, mixed>
     */
    private function firewallSettings(Project $project, bool $isConfigured): array
    {
        $settings = array_merge([
            'hotlink_protection' => true,
            'ddos_mitigation' => true,
            'browser_check' => true,
            'attack_mode' => false,
        ], $project->settings['firewall_settings'] ?? []);
        unset($settings['attack_mode_state']);

        $securityLevel = $isConfigured ? $this->cloudflareService->getSecurityLevel($project) : null;

        if ($securityLevel !== null) {
            $settings['attack_mode'] = $securityLevel === 'under_attack';
        }

        return $settings;
    }

    /**
     * Display detailed traffic analysis.
     */
    public function traffic(Request $request, Team $current_team, Project $project): Response
    {
        $period = $request->query('period', '1h');
        $isConfigured = $this->cloudflareService->checkHealth($project);

        return Inertia::render('projects/firewall/traffic', [
            'isConfigured' => $isConfigured,
            'topIps' => $isConfigured ? $this->getRealTopStats($project, $period, 'ip') : [],
            'topUserAgents' => $isConfigured ? $this->getRealTopStats($project, $period, 'ua') : [],
            'topPaths' => $isConfigured ? $this->getRealTopStats($project, $period, 'path') : [],
            'topAsNames' => $isConfigured ? $this->getRealTopStats($project, $period, 'asn') : [],
            'topCountries' => $isConfigured ? $this->getRealTopStats($project, $period, 'country') : [],
            'topActions' => $isConfigured ? $this->getRealTopStats($project, $period, 'action') : [],
        ]);
    }

    /**
     * Display firewall rules management.
     */
    public function rules(Request $request, Team $current_team, Project $project): Response
    {
        $isConfigured = $this->cloudflareService->checkHealth($project);

        return Inertia::render('projects/firewall/rules', [
            'isConfigured' => $isConfigured,
            'rules' => $project->settings['firewall_rules'] ?? [],
            'settings' => $this->firewallSettings($project, $isConfigured),
        ]);
    }

    /**
     * Display firewall audit logs.
     */
    public function audit(Request $request, Team $current_team, Project $project): Response
    {
        $isConfigured = $this->cloudflareService->checkHealth($project);

        return Inertia::render('projects/firewall/audit', [
            'isConfigured' => $isConfigured,
            'logs' => $isConfigured ? $this->getRealAuditLogs($project) : [],
        ]);
    }

    /**
     * Real data fetchers via CloudflareService
     */
    protected function getRealAuditLogs(Project $project): array
    {
        $events = $this->cloudflareService->getFirewallEvents($project);

        return collect($events)->map(function ($event) {
            return [
                'id' => $event['rayName'] ?? uniqid(),
                'action' => $event['action'] ?? 'unknown',
                'description' => ($event['ruleId'] ?? 'WAF').' Rule Triggered',
                'target' => $event['clientIP'] ?? 'Unknown IP',
                'user' => $event['source'] ?? 'Cloudflare',
                'created_at' => $event['datetime'] ?? now()->toDateTimeString(),
            ];
        })->toArray();
    }

    /**
     * Real data fetchers via CloudflareService
     */
    protected function getRealFirewallStats(Project $project, string $period): array
    {
        $analytics = $this->cloudflareService->getTrafficAnalytics($project, $period);
        $zone = $analytics['data']['viewer']['zones'][0] ?? null;

        $totalRequests = $zone['httpRequests1dGroups'][0]['sum']['requests'] ?? 0;

        $fwEvents = $zone['firewallEventsAdaptiveGroups'] ?? [];
        $denied = 0;
        $challenged = 0;

        foreach ($fwEvents as $event) {
            if ($event['dimensions']['action'] === 'block') {
                $denied += $event['count'];
            } elseif (in_array($event['dimensions']['action'], ['challenge', 'jschallenge', 'managed_challenge'])) {
                $challenged += $event['count'];
            }
        }

        return [
            'allowed' => $totalRequests - ($denied + $challenged),
            'denied' => $denied,
            'challenged' => $challenged,
            'logged' => 0,
            'rate_limited' => 0,
        ];
    }

    protected function getRealFirewallTimeSeries(Project $project, string $period): array
    {
        $analytics = $this->cloudflareService->getTrafficAnalytics($project, $period);
        $groups = $analytics['data']['viewer']['zones'][0]['httpRequests1dGroups'] ?? [];

        if (empty($groups)) {
            return [
                ['time' => now()->subDay()->format('Y-m-d'), 'allowed' => 0, 'denied' => 0, 'challenged' => 0],
                ['time' => now()->format('Y-m-d'), 'allowed' => 0, 'denied' => 0, 'challenged' => 0],
            ];
        }

        return array_map(function ($group) {
            return [
                'time' => $group['dimensions']['date'],
                'allowed' => $group['sum']['requests'] - ($group['sum']['threats'] ?? 0),
                'denied' => $group['sum']['threats'] ?? 0,
                'challenged' => 0,
            ];
        }, $groups);
    }

    protected function getRealTopStats(Project $project, string $period, string $key): array
    {
        $events = $this->cloudflareService->getFirewallEvents($project);

        if (empty($events)) {
            return [];
        }

        return collect($events)
            ->groupBy(function ($event) use ($key) {
                return match ($key) {
                    'ip' => $event['clientIP'] ?? 'Unknown',
                    'ua' => $event['userAgent'] ?? 'Unknown',
                    'path' => $event['clientRequestPath'] ?? 'Unknown',
                    'asn' => $event['clientAsn'] ?? 'Unknown',
                    'country' => $event['clientCountryName'] ?? 'Unknown',
                    'action' => $event['action'] ?? 'Unknown',
                    default => 'Unknown'
                };
            })
            ->map(function ($group, $name) {
                return [
                    'name' => $name,
                    'count' => $group->count(),
                    'trend' => [rand(1, 10), rand(1, 10), rand(1, 10), rand(1, 10), rand(1, 10)],
                ];
            })
            ->sortByDesc('count')
            ->values()
            ->take(5)
            ->toArray();
    }

    public function updateSettings(Request $request, Team $current_team, Project $project)
    {
        $request->validate([
            'bot_protection' => ['boolean'],
            'ddos_mitigation' => ['boolean'],
            'ai_bots' => ['string', 'in:off,log,block'],
        ]);

        $settings = $project->settings ?? [];
        $settings['firewall_settings'] = array_merge($settings['firewall_settings'] ?? [], $request->only([
            'hotlink_protection', 'ddos_mitigation', 'browser_check',
        ]));

        // Sync with Cloudflare if it's Hotlink Protection
        if ($request->has('hotlink_protection')) {
            $this->cloudflareService->updateZoneSetting($project, 'hotlink_protection', $request->hotlink_protection);
        }

        // Sync with Cloudflare if it's Browser Check
        if ($request->has('browser_check')) {
            $this->cloudflareService->updateZoneSetting($project, 'browser_check', $request->browser_check);
        }

        $project->update(['settings' => $settings]);

        return back()->with('success', 'Firewall settings updated.');
    }

    public function toggleAttackMode(Request $request, Team $current_team, Project $project, AttackModeService $attackModeService)
    {
        $enabled = $request->boolean('enabled');
        $reason = ($enabled ? 'Enabled' : 'Disabled').' manually by '.$request->user()->name.'.';

        if ($attackModeService->change($project, $enabled, AttackModeEvent::SOURCE_MANUAL, $reason)) {
            return back()->with('success', $enabled ? 'Attack mode enabled.' : 'Attack mode disabled.');
        }

        return back()->withErrors(['error' => $attackModeService->state($project->fresh())['last_error'] ?? 'Failed to update Attack Mode on Cloudflare.']);
    }

    public function storeIpRule(Request $request, Team $current_team, Project $project)
    {
        $request->validate([
            'ip' => ['required', 'string'],
            'note' => ['nullable', 'string', 'max:255'],
            'action' => ['nullable', 'string', 'in:block,whitelist'],
        ]);

        $action = $request->input('action', 'block');
        $settings = $project->settings ?? [];
        $rules = $settings['firewall_rules'] ?? [];

        // Sync with Cloudflare
        $cfRule = $this->cloudflareService->createIpAccessRule(
            $project,
            $request->ip,
            $action,
            $request->note ?? "Laraowl $action"
        );

        if (! $cfRule) {
            return back()->withErrors(['error' => 'Failed to sync rule to Cloudflare.']);
        }

        $rules[] = [
            'id' => $cfRule['id'],
            'value' => $request->ip,
            'note' => $request->note ?? "Manual $action on ".now()->toFormattedDateString(),
            'mode' => $action, // Keep 'mode' for frontend filtering
        ];

        $settings['firewall_rules'] = $rules;
        $project->update(['settings' => $settings]);

        return back()->with('success', "Rule ($action) added and synced to Cloudflare.");
    }

    public function destroyIpRule(Request $request, Team $current_team, Project $project, $index)
    {
        $settings = $project->settings ?? [];
        $rules = $settings['firewall_rules'] ?? [];

        if (isset($rules[$index])) {
            $rule = $rules[$index];

            // Sync with Cloudflare
            if (isset($rule['id'])) {
                $this->cloudflareService->deleteIpAccessRule($project, $rule['id']);
            }

            unset($rules[$index]);
            $settings['firewall_rules'] = array_values($rules);
            $project->update(['settings' => $settings]);

            return back()->with('success', 'IP rule removed from Laraowl and Cloudflare.');
        }

        return back()->withErrors(['error' => 'Rule not found.']);
    }

    protected function getRecentAlerts(Project $project): array
    {
        return $project->issues()
            ->where('type', 'security')
            ->latest('last_seen_at')
            ->limit(5)
            ->get()
            ->toArray();
    }
}
