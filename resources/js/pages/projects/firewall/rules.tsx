import { Head, usePage, router } from '@inertiajs/react';
import { Shield, Plus, Trash2, X } from 'lucide-react';
import { useState } from 'react';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import AppLayout from '@/layouts/app-layout';
import { ConnectCloudflare } from './components/connect-cloudflare';
import { FirewallNav } from './components/firewall-nav';

const RuleRow = ({
    name,
    description,
    status,
    badge,
    onToggle,
}: {
    name: string;
    description: string;
    status: string;
    badge?: string;
    onToggle?: (checked: boolean) => void;
}) => (
    <div className="group flex items-center justify-between rounded-xl border border-border bg-card p-6 shadow-sm transition-all hover:shadow-md">
        <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
                <span className="text-sm font-black text-foreground">
                    {name}
                </span>
                {badge && (
                    <Badge
                        variant="outline"
                        className="h-4 border-primary/20 bg-primary/10 px-1.5 text-[8px] font-black text-primary uppercase"
                    >
                        {badge}
                    </Badge>
                )}
            </div>
            <p className="text-xs text-muted-foreground">{description}</p>
        </div>
        <div className="flex items-center gap-6">
            <div className="flex items-center gap-2">
                <span className="text-[10px] font-bold text-muted-foreground uppercase">
                    {status}
                </span>
            </div>
            <Switch checked={status !== 'Off'} onCheckedChange={onToggle} />
        </div>
    </div>
);

export default function FirewallRules({
    isConfigured,
    rules,
    settings,
}: {
    isConfigured: boolean;
    rules: any[];
    settings: any;
}) {
    const { props }: any = usePage();
    const teamSlug = props.currentTeam?.slug || props.current_team?.slug;
    const projectSlug =
        props.currentProject?.slug || props.current_project?.slug;

    const [isAddingIp, setIsAddingIp] = useState(false);
    const [isAddingBypass, setIsAddingBypass] = useState(false);
    const [newIp, setNewIp] = useState('');
    const [ipNote, setIpNote] = useState('');
    const [isSubmitting, setIsSubmitting] = useState(false);

    const updateSetting = (key: string, value: any) => {
        router.patch(
            `/${teamSlug}/${projectSlug}/firewall/settings`,
            { [key]: value },
            { preserveScroll: true },
        );
    };

    const toggleAttackMode = () => {
        router.post(
            `/${teamSlug}/${projectSlug}/firewall/attack-mode`,
            { enabled: !settings.attack_mode },
            { preserveScroll: true },
        );
    };

    const deleteRule = (index: number) => {
        if (confirm('Are you sure you want to remove this rule?')) {
            router.delete(
                `/${teamSlug}/${projectSlug}/firewall/rules/ip/${index}`,
                { preserveScroll: true },
            );
        }
    };

    const addIpRule = (
        e: React.FormEvent,
        action: 'block' | 'whitelist' = 'block',
    ) => {
        e.preventDefault();
        setIsSubmitting(true);
        router.post(
            `/${teamSlug}/${projectSlug}/firewall/rules/ip`,
            {
                ip: newIp,
                note: ipNote,
                action: action,
            },
            {
                preserveScroll: true,
                onSuccess: () => {
                    setIsAddingIp(false);
                    setIsAddingBypass(false);
                    setNewIp('');
                    setIpNote('');
                    setIsSubmitting(false);
                },
                onError: () => setIsSubmitting(false),
            },
        );
    };

    const blockRules = rules.filter((r) => r.mode === 'block');
    const bypassRules = rules.filter((r) => r.mode === 'whitelist');

    return (
        <div>
            <Head title="Firewall Rules" />

            <div className="animate-in space-y-8 duration-700 fade-in">
                <FirewallNav active="rules" />

                {!isConfigured ? (
                    <ConnectCloudflare />
                ) : (
                    <div className="relative space-y-8">
                        {/* Add Rule Overlay */}
                        {(isAddingIp || isAddingBypass) && (
                            <div className="fixed inset-0 z-50 flex animate-in items-center justify-center bg-background/80 backdrop-blur-sm duration-200 fade-in">
                                <Card className="w-full max-w-md border-border bg-card shadow-2xl">
                                    <CardHeader className="flex flex-row items-center justify-between border-b border-border/50 p-6">
                                        <CardTitle className="text-sm font-black tracking-widest uppercase">
                                            {isAddingBypass
                                                ? 'Add Bypass Rule'
                                                : 'Add IP Block Rule'}
                                        </CardTitle>
                                        <Button
                                            variant="ghost"
                                            size="icon"
                                            onClick={() => {
                                                setIsAddingIp(false);
                                                setIsAddingBypass(false);
                                            }}
                                            className="h-8 w-8 rounded-full"
                                        >
                                            <X className="size-4" />
                                        </Button>
                                    </CardHeader>
                                    <CardContent className="p-6">
                                        <form
                                            onSubmit={(e) =>
                                                addIpRule(
                                                    e,
                                                    isAddingBypass
                                                        ? 'whitelist'
                                                        : 'block',
                                                )
                                            }
                                            className="space-y-4"
                                        >
                                            <div className="space-y-2">
                                                <label className="text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    IP Address or CIDR
                                                </label>
                                                <Input
                                                    placeholder="e.g. 1.1.1.1 or 192.168.1.0/24"
                                                    value={newIp}
                                                    onChange={(e) =>
                                                        setNewIp(e.target.value)
                                                    }
                                                    required
                                                    className="border-border bg-muted/50"
                                                />
                                            </div>
                                            <div className="space-y-2">
                                                <label className="text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    Note (Optional)
                                                </label>
                                                <Input
                                                    placeholder="Reason for this rule"
                                                    value={ipNote}
                                                    onChange={(e) =>
                                                        setIpNote(
                                                            e.target.value,
                                                        )
                                                    }
                                                    className="border-border bg-muted/50"
                                                />
                                            </div>
                                            <div className="flex gap-3 pt-4">
                                                <Button
                                                    type="button"
                                                    variant="outline"
                                                    onClick={() => {
                                                        setIsAddingIp(false);
                                                        setIsAddingBypass(
                                                            false,
                                                        );
                                                    }}
                                                    className="flex-1 text-[10px] font-black tracking-widest uppercase"
                                                >
                                                    Cancel
                                                </Button>
                                                <Button
                                                    type="submit"
                                                    disabled={isSubmitting}
                                                    className={`flex-1 text-[10px] font-black tracking-widest uppercase ${isAddingBypass ? 'bg-emerald-600 hover:bg-emerald-700' : ''}`}
                                                >
                                                    {isSubmitting
                                                        ? 'Syncing...'
                                                        : 'Add & Sync'}
                                                </Button>
                                            </div>
                                        </form>
                                    </CardContent>
                                </Card>
                            </div>
                        )}

                        {/* DDoS Mitigations */}
                        <section className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div className="flex flex-col gap-1">
                                    <h3 className="text-lg font-black tracking-tight text-foreground">
                                        System Bypass Rules
                                    </h3>
                                    <p className="text-xs text-muted-foreground">
                                        Keep specific IP addresses from being
                                        blocked by Laraowl and Cloudflare
                                        mitigations.
                                    </p>
                                </div>
                                <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => setIsAddingBypass(true)}
                                    className="gap-2 border-border text-[10px] font-black tracking-widest uppercase"
                                >
                                    <Plus className="size-3.5" /> Add Bypass
                                </Button>
                            </div>

                            <div className="space-y-2">
                                {bypassRules.length > 0 ? (
                                    bypassRules.map(
                                        (rule: any, index: number) => (
                                            <div
                                                key={index}
                                                className="flex items-center justify-between rounded-xl border border-border bg-card p-4"
                                            >
                                                <div className="flex items-center gap-4">
                                                    <Badge
                                                        variant="outline"
                                                        className="border-emerald-500/20 bg-emerald-500/5 font-mono text-[10px] text-emerald-500"
                                                    >
                                                        BYPASS: {rule.value}
                                                    </Badge>
                                                    <span className="text-xs text-muted-foreground">
                                                        {rule.note ||
                                                            'Internal System'}
                                                    </span>
                                                </div>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() =>
                                                        deleteRule(
                                                            rules.indexOf(rule),
                                                        )
                                                    }
                                                    className="text-muted-foreground hover:text-red-500"
                                                >
                                                    <Trash2 className="size-3.5" />
                                                </Button>
                                            </div>
                                        ),
                                    )
                                ) : (
                                    <Card className="border-dashed border-border bg-card shadow-lg">
                                        <CardContent className="flex flex-col items-center justify-center space-y-4 p-12 text-center">
                                            <Shield className="size-8 text-muted-foreground/30" />
                                            <p className="text-xs font-medium text-muted-foreground">
                                                No system bypass rules yet.
                                            </p>
                                            <Button
                                                variant="outline"
                                                size="sm"
                                                onClick={() =>
                                                    setIsAddingBypass(true)
                                                }
                                                className="gap-2 border-border text-[10px] font-black tracking-widest uppercase"
                                            >
                                                <Plus className="size-3.5" />{' '}
                                                Add Bypass Rule
                                            </Button>
                                        </CardContent>
                                    </Card>
                                )}
                            </div>
                        </section>

                        {/* IP Blocking */}
                        <section className="space-y-6">
                            <div className="flex items-center justify-between">
                                <div className="flex flex-col gap-1">
                                    <h3 className="text-lg font-black tracking-tight text-foreground">
                                        IP Blocking
                                    </h3>
                                    <p className="text-xs text-muted-foreground">
                                        Block requests from these IP addresses
                                        and CIDR ranges.
                                    </p>
                                </div>
                                <Button
                                    size="sm"
                                    onClick={() => setIsAddingIp(true)}
                                    className="gap-2 text-[10px] font-black tracking-widest uppercase"
                                >
                                    <Plus className="size-3.5" /> Add IP
                                </Button>
                            </div>

                            <div className="space-y-2">
                                {blockRules.length > 0 ? (
                                    blockRules.map(
                                        (rule: any, index: number) => (
                                            <div
                                                key={index}
                                                className="flex items-center justify-between rounded-xl border border-border bg-card p-4"
                                            >
                                                <div className="flex items-center gap-4">
                                                    <Badge
                                                        variant="outline"
                                                        className="font-mono text-[10px]"
                                                    >
                                                        {rule.value}
                                                    </Badge>
                                                    <span className="text-xs text-muted-foreground">
                                                        Blocked{' '}
                                                        {rule.note ||
                                                            'manually'}
                                                    </span>
                                                </div>
                                                <Button
                                                    variant="ghost"
                                                    size="sm"
                                                    onClick={() =>
                                                        deleteRule(
                                                            rules.indexOf(rule),
                                                        )
                                                    }
                                                    className="text-muted-foreground hover:text-red-500"
                                                >
                                                    <Trash2 className="size-3.5" />
                                                </Button>
                                            </div>
                                        ),
                                    )
                                ) : (
                                    <div className="rounded-xl border border-dashed bg-muted/30 p-12 text-center">
                                        <p className="text-xs text-muted-foreground">
                                            No IP blocking rules configured.
                                        </p>
                                    </div>
                                )}
                            </div>
                        </section>

                        {/* Security Features */}
                        <section className="space-y-6">
                            <div className="flex flex-col gap-1">
                                <h3 className="text-lg font-black tracking-tight text-foreground">
                                    Security Features
                                </h3>
                                <p className="text-xs text-muted-foreground">
                                    Configure global security settings for your
                                    site.
                                </p>
                            </div>

                            <div className="grid gap-4">
                                <RuleRow
                                    name="Hotlink Protection"
                                    description="Prevent other websites from linking directly to your image resources to save bandwidth."
                                    status={
                                        settings.hotlink_protection
                                            ? 'On'
                                            : 'Off'
                                    }
                                    onToggle={(checked) =>
                                        updateSetting(
                                            'hotlink_protection',
                                            checked,
                                        )
                                    }
                                />
                                <RuleRow
                                    name="Browser Integrity Check"
                                    description="Evaluate HTTP headers from visitors to identify automated tools and bots."
                                    status={
                                        settings.browser_check ? 'On' : 'Off'
                                    }
                                    onToggle={(checked) =>
                                        updateSetting('browser_check', checked)
                                    }
                                />
                            </div>
                        </section>

                        {/* Danger Zone */}
                        <section className="space-y-6 pt-12">
                            <div className="flex flex-col gap-1">
                                <h3 className="text-lg font-black tracking-tight text-red-500">
                                    Danger Zone
                                </h3>
                            </div>

                            <Card className="overflow-hidden border-red-500/20 bg-red-500/5 shadow-lg">
                                <CardContent className="divide-y divide-red-500/10 p-0">
                                    <div className="flex items-center justify-between p-6">
                                        <div className="flex flex-col gap-1">
                                            <span className="text-sm font-black tracking-widest text-red-500 uppercase">
                                                Attack Mode
                                            </span>
                                            <p className="text-xs text-red-400/80">
                                                Challenge suspicious traffic
                                                with JavaScript verification to
                                                block automated attacks.
                                            </p>
                                        </div>
                                        <Button
                                            variant={
                                                settings.attack_mode
                                                    ? 'outline'
                                                    : 'destructive'
                                            }
                                            size="sm"
                                            onClick={toggleAttackMode}
                                            className={
                                                settings.attack_mode
                                                    ? 'border-red-500 text-red-500 hover:bg-red-500/10'
                                                    : 'bg-red-600 hover:bg-red-700'
                                            }
                                        >
                                            {settings.attack_mode
                                                ? 'Disable Attack Mode'
                                                : 'Enable Attack Mode'}
                                        </Button>
                                    </div>
                                </CardContent>
                            </Card>
                        </section>
                    </div>
                )}
            </div>
        </div>
    );
}

FirewallRules.layout = (page: any) => (
    <AppLayout
        children={page}
        breadcrumbs={[
            { title: 'Firewall', href: '#' },
            { title: 'Rules', href: '#' },
        ]}
    />
);
