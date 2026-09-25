<?php

namespace App\Http\Controllers\Projects;

use App\Http\Controllers\Controller;
use App\Http\Requests\Projects\UpdateAutoAttackModeRequest;
use App\Models\Project;
use App\Models\Team;
use App\Services\AttackModeService;
use App\Services\CloudflareService;
use Illuminate\Http\RedirectResponse;
use Inertia\Inertia;
use Inertia\Response;

class AutoAttackModeController extends Controller
{
    protected const int EVENTS_LIMIT = 30;

    public function __construct(
        protected CloudflareService $cloudflareService,
        protected AttackModeService $attackModeService,
    ) {}

    public function show(Team $current_team, Project $project): Response
    {
        $isConfigured = $this->cloudflareService->checkHealth($project);
        $state = $this->attackModeService->state($project);

        if ($isConfigured && ($securityLevel = $this->cloudflareService->getSecurityLevel($project)) !== null) {
            $state['attack_mode'] = $securityLevel === AttackModeService::UNDER_ATTACK;
        }

        return Inertia::render('projects/firewall/auto-attack-mode', [
            'isConfigured' => $isConfigured,
            'config' => $this->attackModeService->config($project),
            'defaults' => AttackModeService::DEFAULTS,
            'state' => $state,
            'events' => $project->attackModeEvents()
                ->latest('created_at')
                ->latest('id')
                ->limit(self::EVENTS_LIMIT)
                ->get(['id', 'action', 'source', 'reason', 'metrics', 'created_at']),
        ]);
    }

    public function update(UpdateAutoAttackModeRequest $request, Team $current_team, Project $project): RedirectResponse
    {
        $settings = $project->settings ?? [];
        $settings['auto_attack_mode'] = $request->validated();
        $project->update(['settings' => $settings]);

        return back()->with('success', $request->boolean('enabled') ? 'Auto Attack Mode enabled.' : 'Auto Attack Mode settings saved.');
    }
}
