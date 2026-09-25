<?php

use App\Http\Controllers\Projects\AlertRuleController;
use App\Http\Controllers\Projects\AutoAttackModeController;
use App\Http\Controllers\Projects\FirewallController;
use App\Http\Controllers\Projects\IntegrationController;
use App\Http\Controllers\Projects\IssueController;
use App\Http\Controllers\Projects\ProjectController;
use App\Http\Controllers\Projects\RecordController;
use App\Http\Controllers\Projects\ThresholdController;
use App\Http\Controllers\Teams\TeamController;
use App\Http\Controllers\Teams\TeamInvitationController;
use App\Http\Middleware\EnsureProjectExists;
use App\Http\Middleware\EnsureTeamMembership;
use App\Models\Team;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('dashboard', function (Request $request) {
        $user = $request->user();
        $team = $user->currentTeam ?? $user->teams()->first();

        if (! $team) {
            return redirect()->route('teams.create');
        }

        $project = $team->projects()->first();
        if (! $project) {
            return redirect()->route('projects.create', ['current_team' => $team->slug]);
        }

        return redirect()->route('dashboard', ['current_team' => $team->slug, 'project' => $project->slug]);
    });
});

Route::get('/', function () {
    return redirect('/dashboard');
})->name('home');

require __DIR__.'/settings.php';

Route::prefix('{current_team}/{project}')
    ->middleware(['auth', 'verified', EnsureTeamMembership::class, EnsureProjectExists::class])
    ->scopeBindings()
    ->group(function () {
        Route::get('dashboard', [RecordController::class, 'index'])->name('dashboard');

        // Issues
        Route::get('issues', [IssueController::class, 'index'])->name('issues');
        Route::get('issues/{issue}', [IssueController::class, 'show'])->name('issues.show');
        Route::patch('issues/{issue}', [IssueController::class, 'update'])->name('issues.update');
        Route::post('issues/{issue}/comments', [IssueController::class, 'comment'])->name('issues.comment');

        // Monitors (Clean Routes)
        Route::get('requests', [RecordController::class, 'index'])->name('requests');
        Route::get('requests/routes/{hash}', [RecordController::class, 'showDetails'])->name('requests.show');
        Route::get('records/{record}', [RecordController::class, 'showOccurrence'])->name('records.show');

        Route::get('jobs', [RecordController::class, 'index'])->name('jobs');
        Route::get('jobs/types/{hash}', [RecordController::class, 'showJobDetails'])->name('jobs.show');

        Route::get('commands', [RecordController::class, 'index'])->name('commands');
        Route::get('commands/types/{hash}', [RecordController::class, 'showCommandDetails'])->name('commands.show');

        Route::get('scheduled-tasks', [RecordController::class, 'index'])->name('scheduled-tasks');
        Route::get('scheduled-tasks/tasks/{hash}', [RecordController::class, 'showScheduledTaskDetails'])->name('scheduled-tasks.show');

        Route::get('exceptions', [RecordController::class, 'index'])->name('exceptions');
        Route::get('exceptions/types/{hash}', [RecordController::class, 'showExceptionDetails'])->name('exceptions.show');

        Route::get('queries', [RecordController::class, 'index'])->name('queries');
        Route::get('queries/statements/{hash}', [RecordController::class, 'showQueryDetails'])->name('queries.show');

        Route::get('notifications', [RecordController::class, 'index'])->name('notifications');
        Route::get('notifications/channels/{hash}', [RecordController::class, 'showNotificationDetails'])->name('notifications.show');

        Route::get('uptime', [RecordController::class, 'index'])->name('uptime');

        Route::get('mail', [RecordController::class, 'index'])->name('mail');
        Route::get('mail/mailables/{hash}', [RecordController::class, 'showMailDetails'])->name('mail.show');

        Route::get('outgoing-requests', [RecordController::class, 'index'])->name('outgoing-requests');
        Route::get('outgoing-requests/destinations/{hash}', [RecordController::class, 'showOutgoingRequestDetails'])->name('outgoing-requests.show');

        Route::get('users', [RecordController::class, 'index'])->name('users');
        Route::get('users/identifiers/{hash}', [RecordController::class, 'showUserDetails'])->name('users.show');

        Route::get('security', [RecordController::class, 'index'])->name('security');
        Route::get('security/threats/{hash}', [RecordController::class, 'showSecurityDetails'])->name('security.show');

        // Firewall Routes (Top Level)
        Route::get('firewall', [FirewallController::class, 'overview'])->name('firewall.overview');
        Route::get('firewall/traffic', [FirewallController::class, 'traffic'])->name('firewall.traffic');
        Route::get('firewall/rules', [FirewallController::class, 'rules'])->name('firewall.rules');
        Route::get('firewall/audit', [FirewallController::class, 'audit'])->name('firewall.audit');
        Route::get('firewall/auto-attack-mode', [AutoAttackModeController::class, 'show'])->name('firewall.auto-attack-mode');

        // Firewall Actions
        Route::patch('firewall/settings', [FirewallController::class, 'updateSettings'])->name('firewall.settings.update');
        Route::post('firewall/attack-mode', [FirewallController::class, 'toggleAttackMode'])->name('firewall.attack-mode.toggle');
        Route::patch('firewall/auto-attack-mode', [AutoAttackModeController::class, 'update'])->name('firewall.auto-attack-mode.update');
        Route::post('firewall/rules/ip', [FirewallController::class, 'storeIpRule'])->name('firewall.rules.ip.store');
        Route::delete('firewall/rules/ip/{rule_index}', [FirewallController::class, 'destroyIpRule'])->name('firewall.rules.ip.destroy');

        Route::get('cache', [RecordController::class, 'index'])->name('cache');
        Route::get('logs', [RecordController::class, 'index'])->name('logs');

        // Integrations
        Route::get('integrations', [IntegrationController::class, 'index'])->name('integrations.index');
        Route::post('integrations', [IntegrationController::class, 'store'])->name('integrations.store');
        Route::patch('integrations/{integration}', [IntegrationController::class, 'update'])->name('integrations.update');
        Route::delete('integrations/{integration}', [IntegrationController::class, 'destroy'])->name('integrations.destroy');
        Route::post('integrations/{integration}/test', [IntegrationController::class, 'test'])->name('integrations.test');

        // Alert Rules
        Route::get('alerts', [AlertRuleController::class, 'index'])->name('alerts.index');
        Route::post('alerts', [AlertRuleController::class, 'store'])->name('alerts.store');
        Route::patch('alerts/{rule}', [AlertRuleController::class, 'update'])->name('alerts.update');
        Route::delete('alerts/{rule}', [AlertRuleController::class, 'destroy'])->name('alerts.destroy');

        // Thresholds
        Route::post('thresholds', [ThresholdController::class, 'store'])->name('thresholds.store');
        Route::delete('thresholds/{threshold}', [ThresholdController::class, 'destroy'])->name('thresholds.destroy');

        Route::patch('/', [ProjectController::class, 'update'])->name('projects.update');
        Route::patch('cloudflare', [ProjectController::class, 'updateCloudflare'])->name('projects.cloudflare');
        Route::delete('cloudflare', [ProjectController::class, 'disconnectCloudflare'])->name('projects.cloudflare.disconnect');
        Route::delete('/', [ProjectController::class, 'destroy'])->name('projects.destroy');

        Route::get('settings', [IntegrationController::class, 'index'])->name('project.settings');
    });

Route::prefix('{current_team}')
    ->middleware(['auth', 'verified', EnsureTeamMembership::class])
    ->group(function () {
        Route::get('dashboard', function (Team $current_team) {
            $project = $current_team->projects()->first();
            if ($project) {
                return redirect()->route('dashboard', ['current_team' => $current_team->slug, 'project' => $project->slug]);
            }

            return redirect()->route('projects.create', ['current_team' => $current_team->slug]);
        });
        Route::inertia('projects/create', 'projects/create/index')->name('projects.create');
        Route::post('projects', [ProjectController::class, 'store'])->name('projects.store');
    });

Route::middleware(['auth', 'verified'])->group(function () {
    Route::get('invitations/{invitation}/accept', [TeamInvitationController::class, 'accept'])->name('invitations.accept');

    // Teams Onboarding/Management
    Route::get('teams', [TeamController::class, 'index'])->name('teams.index');
    Route::get('teams/create', [TeamController::class, 'create'])->name('teams.create');
    Route::post('teams', [TeamController::class, 'store'])->name('teams.store');
});
