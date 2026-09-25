<?php

namespace App\Http\Controllers\Projects;

use App\Http\Controllers\Controller;
use App\Models\AlertRule;
use App\Models\Project;
use App\Models\Team;
use Illuminate\Http\Request;
use Inertia\Inertia;

class AlertRuleController extends Controller
{
    public function index(Team $current_team, Project $project)
    {
        return Inertia::render('projects/alerts/index', [
            'rules' => $project->alertRules()->with('integrations')->get(),
            'integrations' => $project->integrations()->where('is_enabled', true)->get(),
            'event_types' => [
                ['id' => 'new_exception', 'name' => 'New Exception', 'description' => 'Alert when a new type of exception is detected'],
                ['id' => 'success_rate_drop', 'name' => 'Success Rate Drop', 'description' => 'Alert when success rate falls below a threshold'],
                ['id' => 'high_latency', 'name' => 'High Latency', 'description' => 'Alert when average response time exceeds a threshold'],
                ['id' => 'daily_summary', 'name' => 'Daily Summary', 'description' => 'Send a summary of activity every 24 hours'],
                ['id' => 'attack_mode', 'name' => 'Attack Mode Changes', 'description' => 'Alert when Auto Attack Mode switches Under Attack Mode or fails to act'],
            ],
        ]);
    }

    public function store(Request $request, Team $current_team, Project $project)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'event_type' => 'required|string',
            'settings' => 'nullable|array',
            'integration_ids' => 'nullable|array',
        ]);

        try {
            $rule = $project->alertRules()->create([
                'name' => $validated['name'],
                'event_type' => $validated['event_type'],
                'settings' => $validated['settings'] ?? [],
            ]);

            if (! empty($validated['integration_ids'])) {
                $rule->integrations()->sync($validated['integration_ids']);
            }

            return back()->with('success', 'Alert rule created successfully.');
        } catch (\Exception $e) {
            \Log::error('Failed to save alert rule: '.$e->getMessage());

            return back()->withErrors(['error' => 'Failed to save rule: '.$e->getMessage()]);
        }
    }

    public function update(Request $request, Team $current_team, Project $project, AlertRule $rule)
    {
        $validated = $request->validate([
            'name' => 'required|string|max:255',
            'settings' => 'required|array',
            'is_enabled' => 'required|boolean',
            'integration_ids' => 'array',
        ]);

        $rule->update([
            'name' => $validated['name'],
            'settings' => $validated['settings'],
            'is_enabled' => $validated['is_enabled'],
        ]);

        $rule->integrations()->sync($request->input('integration_ids', []));

        return back()->with('success', 'Alert rule updated successfully.');
    }

    public function destroy(Team $current_team, Project $project, AlertRule $rule)
    {
        $rule->delete();

        return back()->with('success', 'Alert rule deleted successfully.');
    }
}
