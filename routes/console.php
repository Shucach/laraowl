<?php

use Illuminate\Foundation\Inspiring;
use Illuminate\Support\Facades\Artisan;

Artisan::command('inspire', function () {
    $this->comment(Inspiring::quote());
})->purpose('Display an inspiring quote');

use Illuminate\Support\Facades\Schedule;

Schedule::command('projects:check-health')
    ->everyThirtySeconds()
    ->withoutOverlapping(5)
    ->runInBackground();
Schedule::command('firewall:auto-attack-mode')
    ->everyMinute()
    ->withoutOverlapping(5)
    ->runInBackground();
Schedule::command('model:prune')->hourly();
Schedule::command('laraowl:update --check')->daily();
