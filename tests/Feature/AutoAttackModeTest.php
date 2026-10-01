<?php

use App\Models\AttackModeEvent;
use App\Models\Integration;
use App\Models\Issue;
use App\Models\Project;
use App\Models\Record;
use App\Models\RecordRollup;
use App\Models\User;
use App\Services\AttackModeMetrics;
use App\Services\AttackModeService;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Http;
use Inertia\Testing\AssertableInertia as Assert;

/**
 * In-memory stand-in for the Cloudflare zone used by the automation.
 */
class FakeCloudflareZone
{
    public string $level = 'high';

    public bool $readFails = false;

    public bool $patchFails = false;

    /** Accept PATCH requests without actually changing the level. */
    public bool $patchIgnored = false;

    public bool $analyticsFails = false;

    /** Deny firewallEventsAdaptiveGroups like a Free plan zone. */
    public bool $firewallGroupsDenied = false;

    public int $deniedQueries = 0;

    public int $patches = 0;

    /** @var array<string, int> */
    public array $requests = [];

    /** @var array<string, array<string, int>> minute => [ip => count] */
    public array $firewall = [];

    /** @var array<string, int> */
    public array $baseline = [];

    public function fake(): void
    {
        Http::fake(function (Request $request) {
            $url = $request->url();

            if (str_contains($url, 'example.test/hook')) {
                return Http::response('ok');
            }

            if (str_ends_with($url, '/settings/security_level')) {
                if ($request->method() === 'PATCH') {
                    $this->patches++;

                    if ($this->patchFails) {
                        return Http::response(['success' => false, 'errors' => [['code' => 10000, 'message' => 'Authentication error']]], 403);
                    }

                    if (! $this->patchIgnored) {
                        $this->level = $request['value'];
                    }

                    return Http::response(['success' => true, 'result' => ['value' => $this->level]]);
                }

                return $this->readFails
                    ? Http::response(['success' => false], 500)
                    : Http::response(['success' => true, 'result' => ['id' => 'security_level', 'value' => $this->level]]);
            }

            if (str_ends_with($url, '/graphql')) {
                if ($this->analyticsFails) {
                    return Http::response(['errors' => [['message' => 'unavailable']]], 500);
                }

                $isGrouped = str_contains($request['query'], 'firewallEventsAdaptiveGroups');

                if ($isGrouped && $this->firewallGroupsDenied) {
                    $this->deniedQueries++;

                    return Http::response(['data' => null, 'errors' => [[
                        'message' => "zone 'zone-1' does not have access to the path",
                        'path' => ['viewer', 'zones', '0', 'firewall'],
                        'extensions' => ['code' => 'authz'],
                    ]]]);
                }

                $isWindow = str_contains($request['query'], 'firewallEventsAdaptive');
                $zone = ['requests' => $this->groups($isWindow ? $this->requests : $this->baseline)];

                if ($isWindow) {
                    // Raw events carry one sampled row per IP and minute, weighted by sampleInterval
                    $zone['firewall'] = collect($this->firewall)->flatMap(fn (array $ips, string $minute) => collect($ips)
                        ->map(fn (int $count, string $ip) => $isGrouped
                            ? ['count' => $count, 'dimensions' => ['datetimeMinute' => $this->iso($minute), 'clientIP' => $ip]]
                            : ['datetime' => $this->iso($minute), 'clientIP' => $ip, 'sampleInterval' => $count])
                        ->values())->all();
                }

                return Http::response(['data' => ['viewer' => ['zones' => [$zone]]], 'errors' => null]);
            }

            return Http::response(['success' => true]);
        });
    }

    /**
     * Fill the baseline with the given number of minutes at a constant rate.
     */
    public function withBaseline(int $minutes, int $requestsPerMinute): self
    {
        for ($i = 1; $i <= $minutes; $i++) {
            $this->baseline[now()->startOfMinute()->subMinutes(AttackModeMetrics::BASELINE_EXCLUDED_MINUTES + $i)->format('Y-m-d H:i')] = $requestsPerMinute;
        }

        return $this;
    }

    /**
     * @param  array<string, int>  $series
     * @return array<int, array<string, mixed>>
     */
    protected function groups(array $series): array
    {
        return collect($series)
            ->map(fn (int $count, string $minute) => ['count' => $count, 'dimensions' => ['datetimeMinute' => $this->iso($minute)]])
            ->values()
            ->all();
    }

    protected function iso(string $minute): string
    {
        return Carbon::createFromFormat('Y-m-d H:i', $minute)->utc()->format('Y-m-d\TH:i:00\Z');
    }
}

function autoAttackProject(array $config = [], array $firewallSettings = []): Project
{
    $user = User::factory()->create();

    return Project::factory()->create([
        'team_id' => $user->currentTeam->id,
        'settings' => [
            'cloudflare' => ['api_token' => 'token', 'zone_id' => 'zone-1'],
            'auto_attack_mode' => array_merge(['enabled' => true], $config),
            'firewall_settings' => $firewallSettings,
        ],
    ]);
}

function autoAttackRoute(string $name, Project $project): string
{
    return route($name, ['current_team' => $project->team->slug, 'project' => $project->slug]);
}

function minuteKey(int $minutesAgo): string
{
    return now()->startOfMinute()->subMinutes($minutesAgo)->format('Y-m-d H:i');
}

function runAutoAttackMode(): void
{
    test()->artisan('firewall:auto-attack-mode')->assertSuccessful();
}

function attackState(Project $project): array
{
    return $project->fresh()->settings['firewall_settings'];
}

/**
 * Laraowl WAF events: records linked to a high risk security issue.
 */
function wafEvents(Project $project, int $count, int $ips, int $minutesAgo = 0): void
{
    $issue = Issue::create([
        'project_id' => $project->id,
        'hash' => md5(uniqid()),
        'type' => 'security',
        'title' => 'Security Issue: HIGH Risk',
        'message' => 'test',
        'status' => 'open',
        'priority' => 'high',
        'first_seen_at' => now(),
        'last_seen_at' => now(),
    ]);

    for ($i = 0; $i < $count; $i++) {
        Record::factory()->create([
            'project_id' => $project->id,
            'issue_id' => $issue->id,
            'ip' => '10.0.0.'.($i % $ips),
            'created_at' => now()->subMinutes($minutesAgo)->subSeconds(5),
        ]);
    }
}

function serverErrors(Project $project, string $minute, int $count, int $errors): void
{
    RecordRollup::create([
        'project_id' => $project->id,
        'type' => 'request',
        'bucket' => Carbon::createFromFormat('Y-m-d H:i', $minute)->startOfMinute(),
        'count' => $count,
        'server_error_count' => $errors,
    ]);
}

/**
 * A spiking minute with a threat signal from few IPs, so only the traffic criterion can match.
 */
function spikeMinute(FakeCloudflareZone $zone, string $minute, int $requests = 1000): void
{
    $zone->requests[$minute] = $requests;
    $zone->firewall[$minute] = ['1.1.1.1' => (int) ($requests * 0.08), '2.2.2.2' => (int) ($requests * 0.07)];
}

function autoEnabledState(int $minutesAgo): array
{
    return [
        'attack_mode' => true,
        'attack_mode_state' => [
            'source' => AttackModeEvent::SOURCE_AUTOMATIC,
            'changed_at' => now()->subMinutes($minutesAgo)->toIso8601String(),
            'reason' => 'Traffic spike',
        ],
    ];
}

beforeEach(function () {
    $this->travelTo(Carbon::parse('2026-09-25 12:00:00'));
    $this->zone = new FakeCloudflareZone;
    $this->zone->fake();
});

test('auto attack mode is disabled by default for existing projects', function () {
    $user = User::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $user->currentTeam->id,
        'settings' => ['cloudflare' => ['api_token' => 'token', 'zone_id' => 'zone-1']],
    ]);
    wafEvents($project, 50, 10);

    runAutoAttackMode();

    expect($this->zone->patches)->toBe(0)
        ->and($project->attackModeEvents()->count())->toBe(0);

    $this->actingAs($user)
        ->get(autoAttackRoute('firewall.auto-attack-mode', $project))
        ->assertInertia(fn (Assert $page) => $page
            ->component('projects/firewall/auto-attack-mode')
            ->where('config.enabled', false)
            ->where('config.request_rate_threshold', 300)
            ->where('config.quiet_window_minutes', 15)
        );
});

test('a traffic spike with a threat signal enables attack mode only after three consecutive minutes', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);

    spikeMinute($this->zone, minuteKey(1));
    runAutoAttackMode();
    expect($this->zone->level)->toBe('high');

    $this->travel(1)->minutes();
    spikeMinute($this->zone, minuteKey(1));
    runAutoAttackMode();
    expect($this->zone->level)->toBe('high');

    $this->travel(1)->minutes();
    spikeMinute($this->zone, minuteKey(1));
    runAutoAttackMode();

    $state = attackState($project);

    expect($this->zone->level)->toBe('under_attack')
        ->and($this->zone->patches)->toBe(1)
        ->and($state['attack_mode'])->toBeTrue()
        ->and($state['attack_mode_state']['source'])->toBe('automatic')
        ->and($state['attack_mode_state']['reason'])->toContain('3 consecutive minutes')
        ->and($state['attack_mode_state']['metrics']['requests_per_minute'])->toBe(1000)
        ->and($state['attack_mode_state']['metrics']['baseline_requests'])->toEqual(50);

    $event = $project->attackModeEvents()->sole();
    expect($event->action)->toBe('enabled')
        ->and($event->source)->toBe('automatic');
});

test('a spike interrupted by a normal minute does not enable attack mode', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);

    spikeMinute($this->zone, minuteKey(3));
    $this->zone->requests[minuteKey(2)] = 60;
    spikeMinute($this->zone, minuteKey(1));

    runAutoAttackMode();

    expect($this->zone->level)->toBe('high')
        ->and($project->attackModeEvents()->count())->toBe(0);
});

test('a 5xx signal also qualifies a traffic spike', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);

    foreach ([1, 2, 3] as $ago) {
        $this->zone->requests[minuteKey($ago)] = 1000;
        serverErrors($project, minuteKey($ago), 100, 20);
    }

    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and(attackState($project)['attack_mode_state']['reason'])->toContain('5xx rate');
});

test('a unique IP surge also qualifies a traffic spike', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);

    // Baseline: two distinct IPs per minute over the last day
    for ($i = 16; $i < 100; $i++) {
        foreach (['9.9.9.1', '9.9.9.2'] as $ip) {
            Record::factory()->create(['project_id' => $project->id, 'ip' => $ip, 'created_at' => now()->subMinutes($i)->startOfMinute()->addSeconds(10)]);
        }
    }

    foreach ([1, 2, 3] as $ago) {
        $this->zone->requests[minuteKey($ago)] = 1000;

        for ($ip = 0; $ip < 6; $ip++) {
            Record::factory()->create(['project_id' => $project->id, 'ip' => "8.8.8.{$ip}", 'created_at' => now()->subMinutes($ago)->startOfMinute()->addSeconds(10)]);
        }
    }

    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and(attackState($project)['attack_mode_state']['reason'])->toContain('unique IPs');
});

test('an organic spike without threat, 5xx or IP signals does not enable attack mode', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);

    foreach (range(1, 15) as $ago) {
        $this->zone->requests[minuteKey($ago)] = 2000;
        $this->zone->firewall[minuteKey($ago)] = ['1.1.1.1' => 10];
        serverErrors($project, minuteKey($ago), 500, 5);
    }

    runAutoAttackMode();

    expect($this->zone->level)->toBe('high')
        ->and($this->zone->patches)->toBe(0)
        ->and($project->attackModeEvents()->count())->toBe(0);
});

test('high risk waf events enable attack mode only within the rolling window', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);

    wafEvents($project, 20, 5, minutesAgo: 3);
    runAutoAttackMode();
    expect($this->zone->level)->toBe('high');

    wafEvents($project, 19, 5, minutesAgo: 1);
    runAutoAttackMode();
    expect($this->zone->level)->toBe('high');

    wafEvents($project, 1, 1, minutesAgo: 0);
    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and(attackState($project)['attack_mode_state']['reason'])->toContain('20 high/critical WAF events from 5 IPs');
});

test('waf events from too few IPs do not enable attack mode', function () {
    autoAttackProject();
    $this->zone->withBaseline(120, 50);

    wafEvents(Project::first(), 40, 4);
    runAutoAttackMode();

    expect($this->zone->level)->toBe('high');
});

test('a cloudflare firewall event spike enables attack mode', function (int $ips, string $expected) {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 5000);

    $this->zone->requests[minuteKey(1)] = 5000;
    $this->zone->firewall[minuteKey(1)] = collect(range(1, $ips))->mapWithKeys(fn ($i) => ["7.7.7.{$i}" => intdiv(120, $ips) + 1])->all();

    runAutoAttackMode();

    expect($this->zone->level)->toBe($expected);

    if ($expected === 'under_attack') {
        expect(attackState($project)['attack_mode_state']['reason'])->toContain('Cloudflare block/challenge events');
    }
})->with([
    'from many IPs' => [12, 'under_attack'],
    'from too few IPs' => [9, 'high'],
]);

test('zones without grouped firewall analytics fall back to raw firewall events', function () {
    $project = autoAttackProject();
    $this->zone->firewallGroupsDenied = true;
    $this->zone->withBaseline(120, 5000);

    runAutoAttackMode();

    expect($this->zone->level)->toBe('high')
        ->and($project->attackModeEvents()->count())->toBe(0);

    $this->zone->requests[minuteKey(1)] = 5000;
    $this->zone->firewall[minuteKey(1)] = collect(range(1, 12))->mapWithKeys(fn ($i) => ["7.7.7.{$i}" => 11])->all();

    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and(attackState($project)['attack_mode_state']['reason'])->toContain('132 Cloudflare block/challenge events from 12 IPs')
        ->and($this->zone->deniedQueries)->toBe(1);
});

test('without enough baseline history only the absolute thresholds apply', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(30, 1000);

    foreach ([1, 2, 3] as $ago) {
        spikeMinute($this->zone, minuteKey($ago), 400);
    }

    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and(attackState($project)['attack_mode_state']['metrics']['baseline_requests'])->toBeNull();
});

test('with enough baseline history a spike below the baseline multiplier does not enable attack mode', function () {
    autoAttackProject();
    $this->zone->withBaseline(120, 200);

    foreach ([1, 2, 3] as $ago) {
        spikeMinute($this->zone, minuteKey($ago), 400);
    }

    runAutoAttackMode();

    expect($this->zone->level)->toBe('high');
});

test('an automatically enabled mode is disabled after the quiet window but not before the minimum active time', function () {
    $this->zone->level = 'under_attack';
    $project = autoAttackProject(firewallSettings: autoEnabledState(0));
    $this->zone->withBaseline(120, 50);

    $this->travel(9)->minutes();
    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and($this->zone->patches)->toBe(0);

    $this->travel(1)->minutes();
    runAutoAttackMode();

    $state = attackState($project);

    expect($this->zone->level)->toBe('high')
        ->and($this->zone->patches)->toBe(1)
        ->and($state['attack_mode'])->toBeFalse()
        ->and($state['attack_mode_state']['source'])->toBe('automatic')
        ->and($state['attack_mode_state']['auto_disabled_at'])->not->toBeNull()
        ->and($project->attackModeEvents()->latest('id')->first()->action)->toBe('disabled');
});

test('a breach inside the quiet window restarts the countdown', function () {
    $this->zone->level = 'under_attack';
    $project = autoAttackProject(firewallSettings: autoEnabledState(60));
    $this->zone->withBaseline(120, 50);

    // Threat ratio breach 8 minutes ago: only 7 quiet minutes so far
    $this->zone->requests[minuteKey(8)] = 100;
    $this->zone->firewall[minuteKey(8)] = ['1.1.1.1' => 10];

    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and(attackState($project)['attack_mode_state']['quiet_since'])->toBe(Carbon::parse(minuteKey(7))->toIso8601String());

    $this->travel(7)->minutes();
    runAutoAttackMode();
    expect($this->zone->level)->toBe('under_attack');

    $this->travel(1)->minutes();
    runAutoAttackMode();
    expect($this->zone->level)->toBe('high');
});

test('a new high risk waf event keeps an automatic mode active', function () {
    $this->zone->level = 'under_attack';
    autoAttackProject(firewallSettings: autoEnabledState(60));
    $this->zone->withBaseline(120, 50);

    wafEvents(Project::first(), 1, 1, minutesAgo: 10);
    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack');
});

test('a manually enabled mode is never disabled by automation', function () {
    $project = autoAttackProject();
    $user = User::first();

    $this->actingAs($user)
        ->post(autoAttackRoute('firewall.attack-mode.toggle', $project), ['enabled' => true])
        ->assertSessionHasNoErrors();

    expect(attackState($project)['attack_mode_state']['source'])->toBe('manual');

    $this->zone->withBaseline(120, 50);
    $this->travel(60)->minutes();
    runAutoAttackMode();
    $this->travel(1)->minutes();
    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and($this->zone->patches)->toBe(1)
        ->and($project->attackModeEvents()->pluck('action')->all())->toBe(['enabled', 'suppressed'])
        ->and($project->attackModeEvents()->latest('id')->first()->reason)->toContain('enabled manually');
});

test('a manual disable pauses automatic enabling for the cooldown', function () {
    $this->zone->level = 'under_attack';
    $project = autoAttackProject(firewallSettings: autoEnabledState(5));

    $this->actingAs(User::first())
        ->post(autoAttackRoute('firewall.attack-mode.toggle', $project), ['enabled' => false])
        ->assertSessionHasNoErrors();

    expect($this->zone->level)->toBe('high')
        ->and(attackState($project)['attack_mode_state']['manual_disabled_at'])->not->toBeNull();

    $this->zone->withBaseline(120, 50);
    $this->travel(29)->minutes();
    wafEvents($project, 30, 10);
    runAutoAttackMode();

    expect($this->zone->level)->toBe('high')
        ->and($project->attackModeEvents()->latest('id')->first()->action)->toBe('suppressed');

    $this->travel(1)->minutes();
    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and(attackState($project)['attack_mode_state']['source'])->toBe('automatic');
});

test('an automatic disable blocks re-enabling for the cooldown except for the critical waf criterion', function () {
    $project = autoAttackProject(firewallSettings: [
        'attack_mode' => false,
        'attack_mode_state' => ['source' => 'automatic', 'auto_disabled_at' => now()->subMinutes(5)->toIso8601String()],
    ]);
    $this->zone->withBaseline(120, 50);

    foreach ([1, 2, 3] as $ago) {
        spikeMinute($this->zone, minuteKey($ago));
    }

    runAutoAttackMode();

    expect($this->zone->level)->toBe('high')
        ->and($project->attackModeEvents()->sole()->action)->toBe('suppressed');

    wafEvents($project, 20, 5);
    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack');
});

test('a cloudflare error keeps local and actual state in sync and is audited and alerted', function () {
    $project = autoAttackProject();
    $rule = $project->alertRules()->create(['name' => 'Attack Mode', 'event_type' => 'attack_mode', 'settings' => [], 'is_enabled' => true]);
    $rule->integrations()->attach(Integration::create([
        'project_id' => $project->id, 'type' => 'webhook', 'name' => 'Hook', 'data' => ['url' => 'https://example.test/hook'], 'is_enabled' => true,
    ])->id);

    $this->zone->withBaseline(120, 50);
    $this->zone->patchFails = true;
    wafEvents($project, 20, 5);

    runAutoAttackMode();

    $state = attackState($project);
    $event = $project->attackModeEvents()->sole();

    expect($this->zone->level)->toBe('high')
        ->and($state['attack_mode'] ?? false)->toBeFalse()
        ->and($state['attack_mode_state']['last_error'])->toContain('Authentication error')
        ->and($event->action)->toBe('failed')
        ->and($event->reason)->toContain('Authentication error');

    Http::assertSent(fn (Request $request) => $request->url() === 'https://example.test/hook'
        && $request['title'] === '⚠️ Attack Mode automation failed');
});

test('an unconfirmed security level change is treated as a failure', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);
    $this->zone->patchIgnored = true;
    wafEvents($project, 20, 5);

    runAutoAttackMode();

    expect(attackState($project)['attack_mode'] ?? false)->toBeFalse()
        ->and($project->attackModeEvents()->sole()->reason)->toContain("instead of 'under_attack'");
});

test('unavailable cloudflare or telemetry leaves the mode unchanged', function (string $failure) {
    $this->zone->level = 'under_attack';
    $project = autoAttackProject(firewallSettings: autoEnabledState(60));
    $this->zone->withBaseline(120, 50);
    $this->zone->{$failure} = true;

    runAutoAttackMode();
    runAutoAttackMode();

    expect($this->zone->level)->toBe('under_attack')
        ->and($this->zone->patches)->toBe(0)
        ->and(attackState($project)['attack_mode'])->toBeTrue()
        ->and($project->attackModeEvents()->sole()->action)->toBe('failed');
})->with([
    'security level unreadable' => ['readFails'],
    'analytics unavailable' => ['analyticsFails'],
]);

test('repeated runs are idempotent', function () {
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);
    wafEvents($project, 20, 5);

    runAutoAttackMode();
    runAutoAttackMode();
    $this->travel(1)->minutes();
    wafEvents($project, 20, 5);
    runAutoAttackMode();

    expect($this->zone->patches)->toBe(1)
        ->and($project->attackModeEvents()->where('action', 'enabled')->count())->toBe(1);
});

test('a mode enabled outside laraowl is adopted as manual without patching', function () {
    $this->zone->level = 'under_attack';
    $project = autoAttackProject();
    $this->zone->withBaseline(120, 50);

    runAutoAttackMode();

    $state = attackState($project);

    expect($this->zone->patches)->toBe(0)
        ->and($state['attack_mode'])->toBeTrue()
        ->and($state['attack_mode_state']['source'])->toBe('manual');
});

test('automatic changes notify the project integrations', function () {
    $project = autoAttackProject();
    $rule = $project->alertRules()->create(['name' => 'Attack Mode', 'event_type' => 'attack_mode', 'settings' => [], 'is_enabled' => true]);
    $rule->integrations()->attach(Integration::create([
        'project_id' => $project->id, 'type' => 'webhook', 'name' => 'Hook', 'data' => ['url' => 'https://example.test/hook'], 'is_enabled' => true,
    ])->id);

    $this->zone->withBaseline(120, 50);
    wafEvents($project, 20, 5);

    runAutoAttackMode();

    Http::assertSent(fn (Request $request) => $request->url() === 'https://example.test/hook'
        && $request['title'] === '🛡️ Under Attack Mode enabled automatically'
        && $request['fields']['Project'] === $project->name
        && $request['fields']['Waf Events'] === 20
        && str_contains($request['message'], 'WAF events'));
});

test('manual changes are audited', function () {
    $project = autoAttackProject();

    $this->actingAs(User::first())
        ->post(autoAttackRoute('firewall.attack-mode.toggle', $project), ['enabled' => true])
        ->assertRedirect();

    $event = $project->attackModeEvents()->sole();

    expect($event->action)->toBe('enabled')
        ->and($event->source)->toBe('manual')
        ->and(attackState($project)['attack_mode'])->toBeTrue();
});

test('a failed manual change is audited and reported', function () {
    $project = autoAttackProject();
    $this->zone->patchFails = true;

    $this->actingAs(User::first())
        ->post(autoAttackRoute('firewall.attack-mode.toggle', $project), ['enabled' => true])
        ->assertSessionHasErrors('error');

    expect($project->attackModeEvents()->sole()->action)->toBe('failed')
        ->and(attackState($project)['attack_mode'] ?? false)->toBeFalse();
});

test('auto attack mode settings can be saved', function () {
    $project = autoAttackProject(['enabled' => false]);

    $payload = array_merge(AttackModeService::DEFAULTS, [
        'enabled' => true,
        'request_rate_threshold' => 500,
        'quiet_window_minutes' => 20,
    ]);

    $this->actingAs(User::first())
        ->patch(autoAttackRoute('firewall.auto-attack-mode.update', $project), $payload)
        ->assertSessionHasNoErrors()
        ->assertRedirect();

    $config = $project->fresh()->settings['auto_attack_mode'];

    expect($config['enabled'])->toBeTrue()
        ->and($config['request_rate_threshold'])->toBe(500)
        ->and($config['quiet_window_minutes'])->toBe(20);
});

test('auto attack mode settings are validated', function () {
    $project = autoAttackProject();

    $this->actingAs(User::first())
        ->patch(autoAttackRoute('firewall.auto-attack-mode.update', $project), [
            'enabled' => true,
            'request_rate_threshold' => 0,
        ])
        ->assertSessionHasErrors(['request_rate_threshold', 'quiet_window_minutes']);
});

test('the auto attack mode page shows the current state and history', function () {
    $this->zone->level = 'under_attack';
    $project = autoAttackProject(firewallSettings: autoEnabledState(3));
    AttackModeEvent::factory()->automatic()->create(['project_id' => $project->id, 'reason' => 'Traffic spike']);

    $this->actingAs(User::first())
        ->get(autoAttackRoute('firewall.auto-attack-mode', $project))
        ->assertInertia(fn (Assert $page) => $page
            ->where('isConfigured', true)
            ->where('config.enabled', true)
            ->where('state.attack_mode', true)
            ->where('state.source', 'automatic')
            ->has('events', 1)
            ->where('events.0.reason', 'Traffic spike')
        );
});
