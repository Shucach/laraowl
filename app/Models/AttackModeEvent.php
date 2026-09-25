<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\MassPrunable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AttackModeEvent extends Model
{
    use HasFactory, MassPrunable;

    public const ACTION_ENABLED = 'enabled';

    public const ACTION_DISABLED = 'disabled';

    public const ACTION_FAILED = 'failed';

    public const ACTION_SUPPRESSED = 'suppressed';

    public const SOURCE_MANUAL = 'manual';

    public const SOURCE_AUTOMATIC = 'automatic';

    /**
     * Audit events older than this many days are pruned.
     */
    public const RETENTION_DAYS = 90;

    public $timestamps = false;

    protected $fillable = [
        'project_id',
        'action',
        'source',
        'reason',
        'metrics',
        'created_at',
    ];

    protected $casts = [
        'metrics' => 'array',
        'created_at' => 'datetime',
    ];

    public function project(): BelongsTo
    {
        return $this->belongsTo(Project::class);
    }

    public function prunable(): Builder
    {
        return static::where('created_at', '<', now()->subDays(self::RETENTION_DAYS));
    }
}
