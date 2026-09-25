<?php

namespace Database\Factories;

use App\Models\AttackModeEvent;
use App\Models\Project;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<AttackModeEvent>
 */
class AttackModeEventFactory extends Factory
{
    protected $model = AttackModeEvent::class;

    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'project_id' => Project::factory(),
            'action' => AttackModeEvent::ACTION_ENABLED,
            'source' => AttackModeEvent::SOURCE_MANUAL,
            'reason' => $this->faker->sentence(),
            'metrics' => null,
            'created_at' => now(),
        ];
    }

    public function automatic(): static
    {
        return $this->state(fn () => ['source' => AttackModeEvent::SOURCE_AUTOMATIC]);
    }
}
