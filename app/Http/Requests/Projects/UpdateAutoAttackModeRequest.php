<?php

namespace App\Http\Requests\Projects;

use Illuminate\Contracts\Validation\ValidationRule;
use Illuminate\Foundation\Http\FormRequest;

class UpdateAutoAttackModeRequest extends FormRequest
{
    /**
     * Determine if the user is authorized to make this request.
     *
     * Project access is enforced by the route group middleware.
     */
    public function authorize(): bool
    {
        return true;
    }

    /**
     * Get the validation rules that apply to the request.
     *
     * @return array<string, ValidationRule|array<mixed>|string>
     */
    public function rules(): array
    {
        return [
            'enabled' => ['required', 'boolean'],
            'request_rate_threshold' => ['required', 'integer', 'min:1', 'max:10000000'],
            'request_rate_multiplier' => ['required', 'numeric', 'min:1', 'max:100'],
            'spike_window_minutes' => ['required', 'integer', 'min:1', 'max:60'],
            'threat_ratio_threshold' => ['required', 'numeric', 'min:0', 'max:100'],
            'error_rate_threshold' => ['required', 'numeric', 'min:0', 'max:100'],
            'unique_ip_multiplier' => ['required', 'numeric', 'min:1', 'max:100'],
            'waf_events_threshold' => ['required', 'integer', 'min:1', 'max:100000'],
            'waf_unique_ips_threshold' => ['required', 'integer', 'min:1', 'max:100000'],
            'waf_window_minutes' => ['required', 'integer', 'min:1', 'max:60'],
            'firewall_events_threshold' => ['required', 'integer', 'min:1', 'max:10000000'],
            'firewall_unique_ips_threshold' => ['required', 'integer', 'min:1', 'max:100000'],
            'min_active_minutes' => ['required', 'integer', 'min:1', 'max:1440'],
            'quiet_window_minutes' => ['required', 'integer', 'min:1', 'max:60'],
            'quiet_request_multiplier' => ['required', 'numeric', 'min:1', 'max:100'],
            'quiet_request_rate_threshold' => ['required', 'integer', 'min:1', 'max:10000000'],
            'quiet_threat_ratio_threshold' => ['required', 'numeric', 'min:0', 'max:100'],
            'quiet_error_rate_threshold' => ['required', 'numeric', 'min:0', 'max:100'],
            'manual_cooldown_minutes' => ['required', 'integer', 'min:0', 'max:1440'],
            'reenable_cooldown_minutes' => ['required', 'integer', 'min:0', 'max:1440'],
        ];
    }
}
