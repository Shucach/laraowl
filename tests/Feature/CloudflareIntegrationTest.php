<?php

use App\Models\Project;
use App\Models\User;
use Illuminate\Support\Facades\Http;
use Inertia\Testing\AssertableInertia as Assert;

function cloudflareProject(User $user, array $settings = []): Project
{
    return Project::factory()->create([
        'team_id' => $user->currentTeam->id,
        'settings' => $settings,
    ]);
}

function projectRoute(string $name, Project $project): string
{
    return route($name, ['current_team' => $project->team->slug, 'project' => $project->slug]);
}

test('settings page reports cloudflare as disconnected by default', function () {
    $user = User::factory()->create();
    $project = cloudflareProject($user);

    $this->actingAs($user)
        ->get(projectRoute('project.settings', $project))
        ->assertInertia(fn (Assert $page) => $page
            ->where('cloudflare.connected', false)
            ->where('cloudflare.zone_id', null)
        );
});

test('settings page reports a connected zone without exposing the token', function () {
    $user = User::factory()->create();
    $project = cloudflareProject($user, [
        'cloudflare' => [
            'api_token' => 'secret-token-abcd',
            'zone_id' => 'zone-123',
            'connected_at' => '2026-09-24T10:00:00+00:00',
        ],
    ]);

    $response = $this->actingAs($user)->get(projectRoute('project.settings', $project));

    $response->assertInertia(fn (Assert $page) => $page
        ->where('cloudflare.connected', true)
        ->where('cloudflare.zone_id', 'zone-123')
        ->where('cloudflare.token_hint', 'abcd')
        ->where('cloudflare.connected_at', '2026-09-24T10:00:00+00:00')
    );

    expect($response->getContent())->not->toContain('secret-token-abcd');
});

test('connecting cloudflare stores verified credentials', function () {
    Http::fake(['api.cloudflare.com/*' => Http::response(['success' => true])]);

    $user = User::factory()->create();
    $project = cloudflareProject($user);

    $this->actingAs($user)
        ->patch(projectRoute('projects.cloudflare', $project), [
            'api_token' => 'token-wxyz',
            'zone_id' => 'zone-456',
        ])
        ->assertSessionHasNoErrors()
        ->assertRedirect();

    $settings = $project->fresh()->settings['cloudflare'];

    expect($settings['api_token'])->toBe('token-wxyz')
        ->and($settings['zone_id'])->toBe('zone-456')
        ->and($settings['connected_at'])->not->toBeNull();
});

test('cloudflare can be disconnected while keeping other settings', function () {
    $user = User::factory()->create();
    $project = cloudflareProject($user, [
        'cloudflare' => ['api_token' => 'token', 'zone_id' => 'zone'],
        'firewall_rules' => [['id' => 'rule-1']],
    ]);

    $this->actingAs($user)
        ->delete(projectRoute('projects.cloudflare.disconnect', $project))
        ->assertRedirect();

    $settings = $project->fresh()->settings;

    expect($settings)->not->toHaveKey('cloudflare')
        ->and($settings['firewall_rules'])->toBe([['id' => 'rule-1']]);
});
