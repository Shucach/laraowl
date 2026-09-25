<?php

use App\Enums\TeamRole;
use App\Models\Project;
use App\Models\Team;
use App\Models\User;

test('a project is created with the team owner as default alert email', function () {
    $owner = User::factory()->create(['email' => 'owner@example.com']);
    $team = Team::factory()->create();
    $team->members()->attach($owner, ['role' => TeamRole::Owner->value]);

    $this->artisan('laraowl:projects:create', [
        'team' => $team->slug,
        'name' => 'My App',
        '--url' => 'https://example.com',
    ])->assertExitCode(0);

    $project = Project::where('name', 'My App')->firstOrFail();

    expect($project->team_id)->toBe($team->id)
        ->and($project->url)->toBe('https://example.com')
        ->and($project->api_token)->not->toBeNull()
        ->and($project->integrations)->toHaveCount(1)
        ->and($project->integrations->first()->data['email'])->toBe('owner@example.com')
        ->and($project->alertRules)->toHaveCount(5);
});

test('the default alert email can be overridden with --email', function () {
    $owner = User::factory()->create();
    $team = Team::factory()->create();
    $team->members()->attach($owner, ['role' => TeamRole::Owner->value]);

    $this->artisan('laraowl:projects:create', [
        'team' => $team->slug,
        'name' => 'My App',
        '--email' => 'alerts@example.com',
    ])->assertExitCode(0);

    $project = Project::where('name', 'My App')->firstOrFail();

    expect($project->integrations->first()->data['email'])->toBe('alerts@example.com');
});

test('project creation fails for an unknown team', function () {
    $this->artisan('laraowl:projects:create', ['team' => 'missing-team', 'name' => 'My App'])
        ->assertExitCode(1);
});

test('project creation fails when the team has no owner and no --email is given', function () {
    $team = Team::factory()->create();

    $this->artisan('laraowl:projects:create', ['team' => $team->slug, 'name' => 'My App'])
        ->assertExitCode(1);

    $this->assertDatabaseMissing('projects', ['name' => 'My App']);
});
