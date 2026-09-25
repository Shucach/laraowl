<?php

namespace App\Console\Commands;

use App\Models\AttackModeEvent;
use App\Models\Project;
use App\Services\AttackModeService;
use App\Services\AutoAttackModeEvaluator;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;
use Throwable;

class EvaluateAutoAttackMode extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'firewall:auto-attack-mode';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Enable or disable Cloudflare Under Attack Mode for projects with Auto Attack Mode';

    /**
     * Execute the console command.
     *
     * The scheduler runs this every minute; each project is evaluated
     * independently so one failing zone does not block the others.
     */
    public function handle(AutoAttackModeEvaluator $evaluator, AttackModeService $attackModeService): int
    {
        $outcomes = [];

        Project::query()->whereNotNull('settings')->lazyById()->each(function (Project $project) use ($evaluator, $attackModeService, &$outcomes) {
            if (! $attackModeService->config($project)['enabled']) {
                return;
            }

            try {
                $outcome = $evaluator->evaluate($project);
            } catch (Throwable $e) {
                Log::error("Auto Attack Mode failed for project {$project->slug}: ".$e->getMessage());
                $attackModeService->fail($project, AttackModeEvent::SOURCE_AUTOMATIC, 'Evaluation error: '.$e->getMessage());
                $outcome = AutoAttackModeEvaluator::OUTCOME_FAILED;
            }

            $outcomes[$outcome] = ($outcomes[$outcome] ?? 0) + 1;
        });

        $this->info('Auto Attack Mode evaluated: '.(collect($outcomes)->map(fn ($count, $outcome) => "{$outcome}={$count}")->implode(', ') ?: 'no projects'));

        return self::SUCCESS;
    }
}
