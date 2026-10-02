import { Head, router, useForm, usePage } from '@inertiajs/react';
import {
    AlertTriangle,
    Bot,
    Clock,
    Hand,
    RotateCcw,
    ShieldAlert,
    ShieldCheck,
} from 'lucide-react';
import InputError from '@/components/input-error';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import AppLayout from '@/layouts/app-layout';
import { toggle as toggleAttackModeRoute } from '@/routes/firewall/attack-mode';
import { update as updateAutoAttackMode } from '@/routes/firewall/auto-attack-mode';
import { ConnectCloudflare } from './components/connect-cloudflare';
import { FirewallNav } from './components/firewall-nav';

type AutoAttackModeConfig = {
    enabled: boolean;
    request_rate_threshold: number;
    request_rate_multiplier: number;
    spike_window_minutes: number;
    threat_ratio_threshold: number;
    error_rate_threshold: number;
    unique_ip_multiplier: number;
    waf_events_threshold: number;
    waf_unique_ips_threshold: number;
    waf_window_minutes: number;
    firewall_events_threshold: number;
    firewall_unique_ips_threshold: number;
    min_active_minutes: number;
    quiet_window_minutes: number;
    quiet_request_multiplier: number;
    quiet_request_rate_threshold: number;
    quiet_threat_ratio_threshold: number;
    quiet_error_rate_threshold: number;
    manual_cooldown_minutes: number;
    reenable_cooldown_minutes: number;
};

type ThresholdKey = Exclude<keyof AutoAttackModeConfig, 'enabled'>;

type AttackModeState = {
    attack_mode: boolean;
    source: 'manual' | 'automatic' | null;
    changed_at: string | null;
    reason: string | null;
    metrics: Record<string, number | string | null> | null;
    manual_disabled_at: string | null;
    auto_disabled_at: string | null;
    last_evaluated_at: string | null;
    quiet_since: string | null;
    last_error: string | null;
};

type AttackModeEvent = {
    id: number;
    action: 'enabled' | 'disabled' | 'failed' | 'suppressed';
    source: 'manual' | 'automatic';
    reason: string | null;
    metrics: Record<string, number | string | null> | null;
    created_at: string;
};

type Field = {
    key: ThresholdKey;
    label: string;
    unit: string;
    step?: string;
};

const sections: { title: string; description: string; fields: Field[] }[] = [
    {
        title: 'Traffic Spike',
        description:
            "Enable when request rate exceeds both thresholds for consecutive minutes and at least one extra signal fires. The threat ratio only counts Cloudflare mitigations above the zone's usual volume.",
        fields: [
            {
                key: 'request_rate_threshold',
                label: 'Request rate',
                unit: 'req/min',
            },
            {
                key: 'request_rate_multiplier',
                label: 'Baseline multiplier',
                unit: 'x',
                step: '0.1',
            },
            {
                key: 'spike_window_minutes',
                label: 'Consecutive minutes',
                unit: 'min',
            },
            {
                key: 'threat_ratio_threshold',
                label: 'Excess threat ratio',
                unit: '%',
                step: '0.1',
            },
            {
                key: 'error_rate_threshold',
                label: 'HTTP 5xx share',
                unit: '%',
                step: '0.1',
            },
            {
                key: 'unique_ip_multiplier',
                label: 'Unique IPs vs baseline',
                unit: 'x',
                step: '0.1',
            },
        ],
    },
    {
        title: 'Laraowl WAF Events',
        description:
            'Enable on high/critical WAF events. This criterion is critical and bypasses the re-enable cooldown.',
        fields: [
            { key: 'waf_events_threshold', label: 'Events', unit: 'events' },
            { key: 'waf_unique_ips_threshold', label: 'From IPs', unit: 'IPs' },
            { key: 'waf_window_minutes', label: 'Rolling window', unit: 'min' },
        ],
    },
    {
        title: 'Cloudflare Firewall Spike',
        description:
            "Enable on a burst of block/challenge events in one minute, counted above the zone's usual volume.",
        fields: [
            {
                key: 'firewall_events_threshold',
                label: 'Events above usual',
                unit: 'events',
            },
            {
                key: 'firewall_unique_ips_threshold',
                label: 'From IPs',
                unit: 'IPs',
            },
        ],
    },
    {
        title: 'Automatic Disable',
        description:
            "Only modes enabled by automation are disabled, once every condition holds for the whole quiet window. Under Attack Mode's own challenges are not counted as traffic.",
        fields: [
            {
                key: 'min_active_minutes',
                label: 'Minimum active time',
                unit: 'min',
            },
            {
                key: 'quiet_window_minutes',
                label: 'Quiet window',
                unit: 'min',
            },
            {
                key: 'quiet_request_multiplier',
                label: 'Request rate below baseline',
                unit: 'x',
                step: '0.1',
            },
            {
                key: 'quiet_request_rate_threshold',
                label: 'Request rate without baseline',
                unit: 'req/min',
            },
            {
                key: 'quiet_threat_ratio_threshold',
                label: 'Excess threat ratio below',
                unit: '%',
                step: '0.1',
            },
            {
                key: 'quiet_error_rate_threshold',
                label: 'HTTP 5xx share below',
                unit: '%',
                step: '0.1',
            },
        ],
    },
    {
        title: 'Flap Protection',
        description:
            'Cooldowns that keep the mode from switching back and forth.',
        fields: [
            {
                key: 'manual_cooldown_minutes',
                label: 'Pause after manual disable',
                unit: 'min',
            },
            {
                key: 'reenable_cooldown_minutes',
                label: 'Re-enable after auto disable',
                unit: 'min',
            },
        ],
    },
];

const metricLabels: Record<string, string> = {
    minute: 'Minute',
    requests_per_minute: 'Requests / min',
    baseline_requests: 'Baseline requests',
    mitigated_per_minute: 'CF mitigated / min',
    baseline_mitigated: 'Baseline mitigated',
    threat_ratio: 'Excess threat ratio %',
    error_rate: '5xx share %',
    unique_ips: 'Unique IPs',
    baseline_unique_ips: 'Baseline unique IPs',
    waf_events: 'WAF events',
    waf_unique_ips: 'WAF IPs',
    firewall_events: 'CF firewall events',
    firewall_unique_ips: 'CF firewall IPs',
};

const formatDate = (value: string | null) =>
    value ? new Date(value).toLocaleString() : '—';

const MetricsList = ({
    metrics,
}: {
    metrics: Record<string, number | string | null> | null;
}) => {
    if (!metrics) {
        return (
            <p className="text-xs text-muted-foreground">
                No metrics recorded.
            </p>
        );
    }

    return (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {Object.entries(metrics).map(([key, value]) => (
                <div
                    key={key}
                    className="rounded-lg border border-border bg-muted/30 px-3 py-2"
                >
                    <div className="text-[9px] font-black tracking-widest text-muted-foreground uppercase">
                        {metricLabels[key] ?? key}
                    </div>
                    <div className="font-mono text-xs font-bold text-foreground">
                        {value ?? '—'}
                    </div>
                </div>
            ))}
        </div>
    );
};

const EventBadge = ({ action }: { action: AttackModeEvent['action'] }) => {
    const styles = {
        enabled: 'border-red-500/20 bg-red-500/10 text-red-500',
        disabled: 'border-emerald-500/20 bg-emerald-500/10 text-emerald-500',
        failed: 'border-orange-500/20 bg-orange-500/10 text-orange-500',
        suppressed: 'border-border bg-muted text-muted-foreground',
    };

    return (
        <Badge
            variant="outline"
            className={`text-[9px] font-black uppercase ${styles[action]}`}
        >
            {action}
        </Badge>
    );
};

const SourceBadge = ({ source }: { source: string | null }) =>
    source ? (
        <Badge
            variant="outline"
            className="gap-1 border-primary/20 bg-primary/10 text-[9px] font-black text-primary uppercase"
        >
            {source === 'automatic' ? (
                <Bot className="size-3" />
            ) : (
                <Hand className="size-3" />
            )}
            {source}
        </Badge>
    ) : null;

export default function FirewallAutoAttackMode({
    isConfigured,
    config,
    defaults,
    state,
    events,
}: {
    isConfigured: boolean;
    config: AutoAttackModeConfig;
    defaults: AutoAttackModeConfig;
    state: AttackModeState;
    events: AttackModeEvent[];
}) {
    const { props }: any = usePage();
    const teamSlug = props.currentTeam?.slug || props.current_team?.slug;
    const projectSlug =
        props.currentProject?.slug || props.current_project?.slug;
    const routeArgs = { current_team: teamSlug, project: projectSlug };

    const form = useForm<AutoAttackModeConfig>(config);

    const save = (e: React.FormEvent) => {
        e.preventDefault();
        form.patch(updateAutoAttackMode.url(routeArgs), {
            preserveScroll: true,
        });
    };

    const toggleAutomation = (enabled: boolean) => {
        form.setData('enabled', enabled);
        router.patch(
            updateAutoAttackMode.url(routeArgs),
            { ...form.data, enabled },
            {
                preserveScroll: true,
                onError: (errors) => {
                    form.setData('enabled', !enabled);
                    form.setError(errors as any);
                },
            },
        );
    };

    const resetToDefaults = () => {
        form.setData({ ...defaults, enabled: form.data.enabled });
    };

    const toggleAttackMode = () => {
        router.post(
            toggleAttackModeRoute.url(routeArgs),
            { enabled: !state.attack_mode },
            { preserveScroll: true },
        );
    };

    return (
        <div>
            <Head title="Auto Attack Mode" />

            <div className="animate-in space-y-8 duration-700 fade-in">
                <FirewallNav active="auto-attack-mode" />

                {!isConfigured ? (
                    <ConnectCloudflare />
                ) : (
                    <div className="space-y-8">
                        {/* Current State */}
                        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
                            <Card
                                className={`overflow-hidden shadow-lg lg:col-span-5 ${
                                    state.attack_mode
                                        ? 'border-red-500/20 bg-red-500/5'
                                        : 'border-border bg-card'
                                }`}
                            >
                                <CardContent className="space-y-6 p-6">
                                    <div className="flex items-start justify-between gap-4">
                                        <div className="flex items-center gap-3">
                                            <div
                                                className={`flex size-10 items-center justify-center rounded-xl border ${
                                                    state.attack_mode
                                                        ? 'border-red-500/20 bg-red-500/10 text-red-500'
                                                        : 'border-emerald-500/20 bg-emerald-500/10 text-emerald-500'
                                                }`}
                                            >
                                                {state.attack_mode ? (
                                                    <ShieldAlert className="size-5" />
                                                ) : (
                                                    <ShieldCheck className="size-5" />
                                                )}
                                            </div>
                                            <div className="flex flex-col">
                                                <span className="text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    Under Attack Mode
                                                </span>
                                                <span
                                                    className={`text-lg font-black ${
                                                        state.attack_mode
                                                            ? 'text-red-500'
                                                            : 'text-emerald-500'
                                                    }`}
                                                >
                                                    {state.attack_mode
                                                        ? 'Active'
                                                        : 'Inactive'}
                                                </span>
                                            </div>
                                        </div>
                                        <SourceBadge source={state.source} />
                                    </div>

                                    <div className="space-y-2 text-xs">
                                        <div className="flex justify-between gap-4">
                                            <span className="text-muted-foreground">
                                                Last change
                                            </span>
                                            <span className="font-bold text-foreground">
                                                {formatDate(state.changed_at)}
                                            </span>
                                        </div>
                                        <div className="flex justify-between gap-4">
                                            <span className="text-muted-foreground">
                                                Last evaluation
                                            </span>
                                            <span className="font-bold text-foreground">
                                                {formatDate(
                                                    state.last_evaluated_at,
                                                )}
                                            </span>
                                        </div>
                                        {state.attack_mode &&
                                            state.source === 'automatic' && (
                                                <div className="flex justify-between gap-4">
                                                    <span className="text-muted-foreground">
                                                        Quiet since
                                                    </span>
                                                    <span className="font-bold text-foreground">
                                                        {formatDate(
                                                            state.quiet_since,
                                                        )}
                                                    </span>
                                                </div>
                                            )}
                                        {state.reason && (
                                            <p className="rounded-lg border border-border bg-muted/30 p-3 text-foreground">
                                                {state.reason}
                                            </p>
                                        )}
                                    </div>

                                    {state.last_error && (
                                        <div className="flex items-start gap-2 rounded-lg border border-orange-500/20 bg-orange-500/10 p-3 text-xs text-orange-500">
                                            <AlertTriangle className="mt-0.5 size-3.5 shrink-0" />
                                            {state.last_error}
                                        </div>
                                    )}

                                    <Button
                                        variant={
                                            state.attack_mode
                                                ? 'outline'
                                                : 'destructive'
                                        }
                                        size="sm"
                                        onClick={toggleAttackMode}
                                        className={`w-full text-[10px] font-black tracking-widest uppercase ${
                                            state.attack_mode
                                                ? 'border-red-500 text-red-500 hover:bg-red-500/10'
                                                : 'bg-red-600 hover:bg-red-700'
                                        }`}
                                    >
                                        {state.attack_mode
                                            ? 'Disable Attack Mode'
                                            : 'Enable Attack Mode'}
                                    </Button>
                                </CardContent>
                            </Card>

                            <Card className="border-border bg-card shadow-lg lg:col-span-7">
                                <CardHeader className="border-b border-border/50 p-6">
                                    <CardTitle className="text-sm font-black tracking-widest uppercase">
                                        Triggering Metrics
                                    </CardTitle>
                                </CardHeader>
                                <CardContent className="p-6">
                                    <MetricsList metrics={state.metrics} />
                                </CardContent>
                            </Card>
                        </div>

                        {/* Automation */}
                        <form onSubmit={save} className="space-y-6">
                            <div className="flex items-center justify-between rounded-xl border border-border bg-card p-6 shadow-sm">
                                <div className="flex flex-col gap-1">
                                    <div className="flex items-center gap-2">
                                        <Bot className="size-4 text-primary" />
                                        <span className="text-sm font-black text-foreground">
                                            Auto Attack Mode
                                        </span>
                                    </div>
                                    <p className="text-xs text-muted-foreground">
                                        Checks traffic every minute and switches
                                        Cloudflare Under Attack Mode on and off
                                        automatically. A mode enabled manually
                                        is never disabled by automation.
                                    </p>
                                </div>
                                <div className="flex items-center gap-6">
                                    <span className="text-[10px] font-bold text-muted-foreground uppercase">
                                        {form.data.enabled ? 'On' : 'Off'}
                                    </span>
                                    <Switch
                                        checked={form.data.enabled}
                                        onCheckedChange={toggleAutomation}
                                        disabled={form.processing}
                                    />
                                </div>
                            </div>

                            <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
                                {sections.map((section) => (
                                    <Card
                                        key={section.title}
                                        className="border-border bg-card shadow-lg"
                                    >
                                        <CardHeader className="space-y-1 border-b border-border/50 p-6">
                                            <CardTitle className="text-sm font-black tracking-widest uppercase">
                                                {section.title}
                                            </CardTitle>
                                            <p className="text-xs text-muted-foreground">
                                                {section.description}
                                            </p>
                                        </CardHeader>
                                        <CardContent className="grid grid-cols-1 gap-4 p-6 sm:grid-cols-2">
                                            {section.fields.map((field) => (
                                                <div
                                                    key={field.key}
                                                    className="space-y-2"
                                                >
                                                    <label
                                                        htmlFor={field.key}
                                                        className="text-[10px] font-black tracking-widest text-muted-foreground uppercase"
                                                    >
                                                        {field.label}
                                                    </label>
                                                    <div className="relative">
                                                        <Input
                                                            id={field.key}
                                                            type="number"
                                                            min="0"
                                                            step={
                                                                field.step ??
                                                                '1'
                                                            }
                                                            value={
                                                                form.data[
                                                                    field.key
                                                                ]
                                                            }
                                                            onChange={(e) =>
                                                                form.setData(
                                                                    field.key,
                                                                    Number(
                                                                        e.target
                                                                            .value,
                                                                    ),
                                                                )
                                                            }
                                                            className="border-border bg-muted/50 pr-16"
                                                        />
                                                        <span className="absolute top-1/2 right-3 -translate-y-1/2 text-[10px] font-bold text-muted-foreground">
                                                            {field.unit}
                                                        </span>
                                                    </div>
                                                    <InputError
                                                        message={
                                                            form.errors[
                                                                field.key
                                                            ]
                                                        }
                                                    />
                                                </div>
                                            ))}
                                        </CardContent>
                                    </Card>
                                ))}
                            </div>

                            <div className="flex justify-end gap-3">
                                <Button
                                    type="button"
                                    variant="outline"
                                    size="sm"
                                    onClick={resetToDefaults}
                                    className="gap-2 border-border text-[10px] font-black tracking-widest uppercase"
                                >
                                    <RotateCcw className="size-3.5" /> Reset to
                                    defaults
                                </Button>
                                <Button
                                    type="submit"
                                    size="sm"
                                    disabled={form.processing}
                                    className="text-[10px] font-black tracking-widest uppercase"
                                >
                                    {form.processing
                                        ? 'Saving...'
                                        : 'Save Thresholds'}
                                </Button>
                            </div>
                        </form>

                        {/* Audit */}
                        <section className="space-y-6">
                            <div className="flex flex-col gap-1">
                                <h3 className="text-lg font-black tracking-tight text-foreground">
                                    Attack Mode History
                                </h3>
                                <p className="text-xs text-muted-foreground">
                                    Every manual and automatic change, failed
                                    attempt and held-back transition.
                                </p>
                            </div>

                            <Card className="overflow-hidden border-border bg-card shadow-xl">
                                <div className="overflow-x-auto">
                                    <table className="w-full border-collapse text-left">
                                        <thead>
                                            <tr className="border-b border-border bg-muted/30">
                                                <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    Action
                                                </th>
                                                <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    Source
                                                </th>
                                                <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    Reason
                                                </th>
                                                <th className="p-4 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    Date
                                                </th>
                                            </tr>
                                        </thead>
                                        <tbody className="divide-y divide-border">
                                            {events.map((event) => (
                                                <tr
                                                    key={event.id}
                                                    className="group transition-colors hover:bg-muted/20"
                                                >
                                                    <td className="p-4">
                                                        <EventBadge
                                                            action={
                                                                event.action
                                                            }
                                                        />
                                                    </td>
                                                    <td className="p-4">
                                                        <SourceBadge
                                                            source={
                                                                event.source
                                                            }
                                                        />
                                                    </td>
                                                    <td className="p-4 text-xs text-foreground">
                                                        {event.reason}
                                                    </td>
                                                    <td className="p-4">
                                                        <div className="flex items-center gap-2 text-xs whitespace-nowrap text-muted-foreground">
                                                            <Clock className="size-3.5" />
                                                            {formatDate(
                                                                event.created_at,
                                                            )}
                                                        </div>
                                                    </td>
                                                </tr>
                                            ))}
                                            {events.length === 0 && (
                                                <tr>
                                                    <td
                                                        colSpan={4}
                                                        className="p-12 text-center text-xs text-muted-foreground"
                                                    >
                                                        No attack mode changes
                                                        recorded yet.
                                                    </td>
                                                </tr>
                                            )}
                                        </tbody>
                                    </table>
                                </div>
                            </Card>
                        </section>
                    </div>
                )}
            </div>
        </div>
    );
}

FirewallAutoAttackMode.layout = (page: any) => (
    <AppLayout
        children={page}
        breadcrumbs={[
            { title: 'Firewall', href: '#' },
            { title: 'Auto Attack Mode', href: '#' },
        ]}
    />
);
