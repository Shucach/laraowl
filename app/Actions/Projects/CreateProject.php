<?php

namespace App\Actions\Projects;

use App\Models\Project;
use App\Models\Team;
use Illuminate\Support\Str;

class CreateProject
{
    /**
     * Create a project with its default email integration and default alert rules.
     */
    public function handle(Team $team, string $name, ?string $url, string $alertEmail): Project
    {
        $project = $team->projects()->create([
            'name' => $name,
            'url' => $url,
            'api_token' => Str::random(32),
            'uptime_check_interval' => 60,
        ]);

        $integration = $project->integrations()->create([
            'name' => 'Default Email',
            'type' => 'email',
            'data' => ['email' => $alertEmail],
            'is_enabled' => true,
        ]);

        foreach ($this->defaultAlertRules() as $ruleData) {
            $rule = $project->alertRules()->create($ruleData + ['is_enabled' => true]);
            $rule->integrations()->attach($integration->id);
        }

        return $project;
    }

    /**
     * @return array<int, array{name: string, event_type: string, settings: array<string, mixed>}>
     */
    protected function defaultAlertRules(): array
    {
        return [
            [
                'name' => 'Critical Exceptions',
                'event_type' => 'new_exception',
                'settings' => ['frequency' => 'immediate'],
            ],
            [
                'name' => 'Site DOWN Alert',
                'event_type' => 'uptime_down',
                'settings' => ['frequency' => 'immediate'],
            ],
            [
                'name' => 'Error Spike Detected',
                'event_type' => 'error_spike',
                'settings' => ['threshold' => 50, 'period' => 1],
            ],
            [
                'name' => 'Background Job Failed',
                'event_type' => 'heartbeat_failed',
                'settings' => ['frequency' => 'immediate'],
            ],
            [
                'name' => 'Attack Mode Changes',
                'event_type' => 'attack_mode',
                'settings' => ['frequency' => 'immediate'],
            ],
        ];
    }
}
