<?php

use App\Models\Project;
use App\Models\Team;
use App\Services\AlertService;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Promise\RejectedPromise;
use GuzzleHttp\Psr7\Request;
use Illuminate\Console\Scheduling\Schedule;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Facades\Http;

uses(RefreshDatabase::class);

test('it logs up when the check succeeds on the first try', function () {
    $team = Team::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'last_uptime_status' => null,
    ]);

    Http::fake([
        '*' => Http::response('OK', 200),
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldNotReceive('notifyUptimeDown');
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    $project->refresh();
    expect($project->last_uptime_status)->toBe('up');
    expect($project->uptimeChecks)->toHaveCount(1);
    expect($project->uptimeChecks->first()->status)->toBe('up');
});

test('it logs up when the check fails on the first try but succeeds on the retry', function () {
    $team = Team::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'last_uptime_status' => null,
    ]);

    $attempts = 0;
    Http::fake([
        '*' => function ($request) use (&$attempts) {
            $attempts++;
            if ($attempts === 1) {
                return new RejectedPromise(
                    new ConnectException(
                        'cURL error 28: Operation timed out',
                        new Request('GET', $request->url())
                    )
                );
            }

            return Http::response('OK', 200);
        },
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldNotReceive('notifyUptimeDown');
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    $project->refresh();
    expect($project->last_uptime_status)->toBe('up');
    expect($project->uptimeChecks)->toHaveCount(1);
    expect($project->uptimeChecks->first()->status)->toBe('up');
});

test('it skips projects with uptime monitoring disabled', function () {
    $team = Team::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'uptime_monitoring_enabled' => false,
        'last_uptime_status' => null,
    ]);

    Http::fake([
        '*' => Http::response('OK', 200),
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldNotReceive('notifyUptimeDown');
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    Http::assertNothingSent();

    $project->refresh();
    expect($project->last_uptime_status)->toBeNull();
    expect($project->last_uptime_check_at)->toBeNull();
    expect($project->uptimeChecks)->toHaveCount(0);
});

test('it does not alert for a disabled project that was previously down', function () {
    $team = Team::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'uptime_monitoring_enabled' => false,
        'uptime_check_interval' => 30,
        'last_uptime_status' => 'down',
    ]);

    Http::fake([
        '*' => Http::response('OK', 200),
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldNotReceive('notifyUptimeDown');
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    Http::assertNothingSent();

    $project->refresh();
    expect($project->last_uptime_status)->toBe('down');
    expect($project->uptimeChecks)->toHaveCount(0);
});

test('it logs down and sends alert when all attempts fail', function () {
    $team = Team::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'last_uptime_status' => 'up',
    ]);

    Http::fake([
        '*' => function ($request) {
            return new RejectedPromise(
                new ConnectException(
                    'cURL error 28: Operation timed out',
                    new Request('GET', $request->url())
                )
            );
        },
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldReceive('notifyUptimeDown')
        ->once()
        ->with(Mockery::on(function ($p) use ($project) {
            return $p->id === $project->id;
        }), 0, 'cURL error 28: Operation timed out');
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    $project->refresh();
    expect($project->last_uptime_status)->toBe('down');
    expect($project->uptimeChecks)->toHaveCount(1);
    expect($project->uptimeChecks->first()->status)->toBe('down');
});

test('it logs up without retrying when cloudflare serves a challenge', function (int $status, array $headers, string $body) {
    $team = Team::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'last_uptime_status' => 'up',
    ]);

    Http::fake([
        '*' => Http::response($body, $status, $headers),
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldNotReceive('notifyUptimeDown');
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    Http::assertSentCount(1);

    $project->refresh();
    $check = $project->uptimeChecks->first();
    expect($project->last_uptime_status)->toBe('up');
    expect($check->status)->toBe('up');
    expect($check->status_code)->toBe($status);
    expect($check->error)->toBe('Cloudflare challenge');
})->with([
    'under attack mode' => [503, ['Server' => 'cloudflare', 'cf-mitigated' => 'challenge'], '<title>Just a moment...</title>'],
    'managed challenge' => [403, ['Server' => 'cloudflare', 'cf-mitigated' => 'challenge'], '<title>Just a moment...</title>'],
    'challenge page without header' => [503, ['Server' => 'cloudflare'], '<script>window._cf_chl_opt={cType: "managed"};</script>'],
]);

test('it still logs down for real errors served through cloudflare', function () {
    $team = Team::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'last_uptime_status' => 'up',
    ]);

    Http::fake([
        '*' => Http::response('Service Unavailable <script src="/cdn-cgi/challenge-platform/scripts/jsd/main.js"></script>', 503, ['Server' => 'cloudflare']),
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldReceive('notifyUptimeDown')->once();
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    Http::assertSentCount(2);

    $project->refresh();
    expect($project->last_uptime_status)->toBe('down');
    expect($project->uptimeChecks->first()->error)->toBe('HTTP error status: 503');
});

test('it recovers to up when a down site switches to a cloudflare challenge', function () {
    $team = Team::factory()->create();
    $project = Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'last_uptime_status' => 'down',
    ]);

    Http::fake([
        '*' => Http::response('<title>Just a moment...</title>', 503, ['Server' => 'cloudflare', 'cf-mitigated' => 'challenge']),
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldNotReceive('notifyUptimeDown');
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->expectsOutputToContain('is back UP')
        ->assertExitCode(0);

    expect($project->refresh()->last_uptime_status)->toBe('up');
});

test('it checks multiple projects concurrently in a single run', function () {
    $team = Team::factory()->create();
    $projects = Project::factory()->count(3)->sequence(
        ['url' => 'https://one.example.com'],
        ['url' => 'https://two.example.com'],
        ['url' => 'https://three.example.com'],
    )->create([
        'team_id' => $team->id,
        'last_uptime_status' => null,
    ]);

    Http::fake([
        'one.example.com' => Http::response('OK', 200),
        'two.example.com' => Http::response('Error', 500),
        'three.example.com' => Http::response('OK', 200),
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldReceive('notifyUptimeDown')->once();
    $this->instance(AlertService::class, $alertService);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    Http::assertSent(fn ($request) => $request->url() === 'https://one.example.com');
    Http::assertSent(fn ($request) => $request->url() === 'https://three.example.com');
    // The failing project is retried once before being marked down.
    Http::assertSentCount(4);

    expect($projects[0]->refresh()->last_uptime_status)->toBe('up');
    expect($projects[1]->refresh()->last_uptime_status)->toBe('down');
    expect($projects[1]->uptimeChecks->first()->status_code)->toBe(500);
    expect($projects[2]->refresh()->last_uptime_status)->toBe('up');
});

test('it performs a single round of checks for sub-minute intervals without sleeping', function () {
    $team = Team::factory()->create();
    Project::factory()->create([
        'team_id' => $team->id,
        'url' => 'https://example.com',
        'uptime_check_interval' => 30,
        'last_uptime_status' => null,
    ]);

    Http::fake([
        '*' => Http::response('OK', 200),
    ]);

    $alertService = Mockery::mock(AlertService::class);
    $alertService->shouldNotReceive('notifyUptimeDown');
    $this->instance(AlertService::class, $alertService);

    $start = microtime(true);

    $this->artisan('projects:check-health')
        ->assertExitCode(0);

    expect(microtime(true) - $start)->toBeLessThan(5);
    Http::assertSentCount(1);
});

test('the health check schedule prevents overlapping runs', function () {
    $event = collect(app(Schedule::class)->events())
        ->first(fn ($event) => str_contains($event->command, 'projects:check-health'));

    expect($event)->not->toBeNull();
    expect($event->withoutOverlapping)->toBeTrue();
    expect($event->expiresAt)->toBe(5);
    expect($event->runInBackground)->toBeTrue();
    expect($event->repeatSeconds)->toBe(30);
});
