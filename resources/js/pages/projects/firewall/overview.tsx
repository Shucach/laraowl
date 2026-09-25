import { Head, Link, usePage, router } from '@inertiajs/react';
import {
    Shield,
    Lock as LockIcon,
    Activity,
    AlertTriangle,
    ChevronRight,
    Globe,
    Filter,
    List,
    LayoutGrid,
    Zap,
    ShieldCheck,
    ArrowUpRight,
    ArrowDownRight,
} from 'lucide-react';
import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer,
} from 'recharts';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import AppLayout from '@/layouts/app-layout';
import { formatCompactNumber } from '@/lib/utils';
import { show as showSecurityThreat } from '@/routes/security';
import { ConnectCloudflare } from './components/connect-cloudflare';

const SecurityScore = ({ score }: { score: number }) => {
    const getColor = (s: number) => {
        if (s > 80) {
            return 'text-emerald-500';
        }

        if (s > 50) {
            return 'text-orange-500';
        }

        return 'text-red-500';
    };

    return (
        <div className="relative flex h-32 w-32 items-center justify-center">
            <svg className="h-full w-full -rotate-90 transform">
                <circle
                    cx="64"
                    cy="64"
                    r="58"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="transparent"
                    className="text-muted/20"
                />
                <circle
                    cx="64"
                    cy="64"
                    r="58"
                    stroke="currentColor"
                    strokeWidth="8"
                    fill="transparent"
                    strokeDasharray={364.4}
                    strokeDashoffset={364.4 - (364.4 * score) / 100}
                    className={`${getColor(score)} transition-all duration-1000 ease-out`}
                />
            </svg>
            <div className="absolute flex flex-col items-center justify-center">
                <span className={`text-2xl font-black ${getColor(score)}`}>
                    {score}%
                </span>
                <span className="text-[8px] font-bold tracking-widest text-muted-foreground uppercase">
                    Security
                </span>
            </div>
        </div>
    );
};

export default function FirewallOverview({
    isConfigured,
    stats,
    timeSeries,
    recentAlerts,
    settings,
}: {
    isConfigured: boolean;
    stats: any;
    timeSeries: any;
    recentAlerts: any;
    settings: any;
}) {
    const { props }: any = usePage();
    const teamSlug = props.currentTeam?.slug || props.current_team?.slug;
    const projectSlug =
        props.currentProject?.slug || props.current_project?.slug;
    const securityThreatHref = (hash: string | number) =>
        showSecurityThreat.url(
            {
                current_team: teamSlug,
                project: projectSlug,
                hash,
            },
            { mergeQuery: {} },
        );

    const toggleAttackMode = () => {
        router.post(
            `/${teamSlug}/${projectSlug}/firewall/attack-mode`,
            { enabled: !settings.attack_mode },
            { preserveScroll: true },
        );
    };

    const navItems = [
        {
            title: 'Overview',
            href: `/${teamSlug}/${projectSlug}/firewall`,
            icon: LayoutGrid,
            active: true,
        },
        {
            title: 'Traffic',
            href: `/${teamSlug}/${projectSlug}/firewall/traffic`,
            icon: Activity,
        },
        {
            title: 'Rules',
            href: `/${teamSlug}/${projectSlug}/firewall/rules`,
            icon: Filter,
        },
        {
            title: 'Audit Log',
            href: `/${teamSlug}/${projectSlug}/firewall/audit`,
            icon: List,
        },
    ];

    // Security Score Calculation based on real-time threats
    const calculateScore = () => {
        const total =
            (stats.allowed || 0) +
            (stats.denied || 0) +
            (stats.challenged || 0);

        if (total === 0) {
            return 100;
        } // Default to 100 if no traffic yet

        const threats = (stats.denied || 0) + (stats.challenged || 0);
        const threatRatio = threats / total;

        // Base score starts at 100 and drops as threat ratio increases
        // A 5% threat ratio (quite high) would drop the score significantly
        let score = 100 - threatRatio * 400;

        // Deduct for recent alerts
        score -= recentAlerts.length * 5;

        return Math.max(Math.round(score), 20);
    };

    const securityScore = calculateScore();

    return (
        <div>
            <Head title="Firewall Overview" />

            <div className="animate-in space-y-8 duration-700 fade-in slide-in-from-bottom-4">
                {/* Secondary Nav */}
                <div className="flex items-center gap-1 border-b border-border/50 pb-4">
                    {navItems.map((item) => (
                        <Link
                            key={item.title}
                            href={item.href}
                            className={`flex items-center gap-2 rounded-lg px-4 py-2 text-xs font-bold transition-all ${
                                item.active
                                    ? 'border border-primary/20 bg-primary/10 text-primary'
                                    : 'text-muted-foreground hover:bg-muted hover:text-foreground'
                            }`}
                        >
                            <item.icon className="size-3.5" />
                            {item.title}
                        </Link>
                    ))}
                </div>

                {!isConfigured ? (
                    <ConnectCloudflare />
                ) : (
                    <div className="space-y-8">
                        {/* Hero Section */}
                        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
                            {/* Security Score Card */}
                            <Card className="group relative overflow-hidden border-border bg-card shadow-2xl lg:col-span-4">
                                <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent opacity-50" />
                                <CardContent className="relative flex flex-col items-center justify-center space-y-6 p-8 text-center">
                                    <SecurityScore score={securityScore} />
                                    <div>
                                        <h2 className="flex items-center justify-center gap-2 text-xl font-black tracking-tight text-foreground">
                                            {securityScore > 80 ? (
                                                <ShieldCheck className="size-5 text-emerald-500" />
                                            ) : (
                                                <Shield className="size-5 text-orange-500" />
                                            )}
                                            {securityScore > 80
                                                ? 'Solid Protection'
                                                : 'Action Required'}
                                        </h2>
                                        <p className="mt-1 text-[10px] font-bold tracking-wider text-muted-foreground uppercase">
                                            Based on active security layers
                                        </p>
                                    </div>
                                    <Button
                                        onClick={toggleAttackMode}
                                        variant={
                                            settings.attack_mode
                                                ? 'destructive'
                                                : 'outline'
                                        }
                                        className="group h-10 w-full text-[10px] font-black tracking-widest uppercase"
                                    >
                                        <Zap
                                            className={`mr-2 size-3.5 ${settings.attack_mode ? 'fill-current' : ''}`}
                                        />
                                        {settings.attack_mode
                                            ? 'Disable Attack Mode'
                                            : 'Enable Attack Mode'}
                                    </Button>
                                </CardContent>
                            </Card>

                            {/* Stats Grid */}
                            <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:col-span-8">
                                <Card className="group relative overflow-hidden border-border bg-card shadow-2xl">
                                    <CardContent className="p-6">
                                        <div className="flex items-start justify-between">
                                            <div className="space-y-2">
                                                <span className="block text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    Allowed Requests
                                                </span>
                                                <div className="text-3xl font-black">
                                                    {formatCompactNumber(
                                                        stats.allowed,
                                                    )}
                                                </div>
                                                <div className="flex items-center gap-1 text-[10px] font-bold text-emerald-500">
                                                    <ArrowUpRight className="size-3" />
                                                    <span>
                                                        Normal Traffic Flow
                                                    </span>
                                                </div>
                                            </div>
                                            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-blue-500/20 bg-blue-500/10 text-blue-500">
                                                <Globe className="size-6" />
                                            </div>
                                        </div>
                                        <div className="mt-6 h-[60px]">
                                            <ResponsiveContainer
                                                width="100%"
                                                height="100%"
                                            >
                                                <AreaChart
                                                    data={timeSeries.slice(-10)}
                                                >
                                                    <Area
                                                        type="monotone"
                                                        dataKey="allowed"
                                                        stroke="#3b82f6"
                                                        fill="#3b82f6"
                                                        fillOpacity={0.1}
                                                        strokeWidth={2}
                                                    />
                                                </AreaChart>
                                            </ResponsiveContainer>
                                        </div>
                                    </CardContent>
                                </Card>

                                <Card className="group relative overflow-hidden border-border bg-card shadow-2xl">
                                    <CardContent className="p-6">
                                        <div className="flex items-start justify-between">
                                            <div className="space-y-2">
                                                <span className="block text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                    Blocked Threats
                                                </span>
                                                <div className="text-3xl font-black text-red-500">
                                                    {formatCompactNumber(
                                                        stats.denied +
                                                            stats.challenged,
                                                    )}
                                                </div>
                                                <div className="flex items-center gap-1 text-[10px] font-bold text-emerald-500">
                                                    <ShieldCheck className="size-3" />
                                                    <span>Fully Mitigated</span>
                                                </div>
                                            </div>
                                            <div className="flex h-12 w-12 items-center justify-center rounded-xl border border-red-500/20 bg-red-500/10 text-red-500">
                                                <Shield className="size-6" />
                                            </div>
                                        </div>
                                        <div className="mt-6 h-[60px]">
                                            <ResponsiveContainer
                                                width="100%"
                                                height="100%"
                                            >
                                                <AreaChart
                                                    data={timeSeries.slice(-10)}
                                                >
                                                    <Area
                                                        type="monotone"
                                                        dataKey="denied"
                                                        stroke="#ef4444"
                                                        fill="#ef4444"
                                                        fillOpacity={0.1}
                                                        strokeWidth={2}
                                                    />
                                                </AreaChart>
                                            </ResponsiveContainer>
                                        </div>
                                    </CardContent>
                                </Card>
                            </div>
                        </div>

                        {/* Middle Section: Chart & Alerts */}
                        <div className="grid grid-cols-1 gap-6 lg:grid-cols-12">
                            <Card className="overflow-hidden border-border bg-card shadow-2xl lg:col-span-8">
                                <CardHeader className="flex flex-row items-center justify-between">
                                    <div className="space-y-1">
                                        <CardTitle className="flex items-center gap-2 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                            <Activity className="size-3.5 text-primary" />
                                            Security Traffic Analysis
                                        </CardTitle>
                                        <p className="text-[9px] font-medium text-muted-foreground">
                                            Real-time threat mitigation across
                                            all zones
                                        </p>
                                    </div>
                                    <div className="flex gap-2">
                                        <Badge
                                            variant="outline"
                                            className="border-emerald-500/20 bg-emerald-500/5 text-[9px] font-bold text-emerald-500"
                                        >
                                            LIVE
                                        </Badge>
                                        <Badge
                                            variant="outline"
                                            className="border-primary/20 bg-primary/5 text-[9px] font-bold text-primary"
                                        >
                                            24H WINDOW
                                        </Badge>
                                    </div>
                                </CardHeader>
                                <CardContent className="h-[350px] p-6">
                                    <ResponsiveContainer
                                        width="100%"
                                        height="100%"
                                    >
                                        <AreaChart
                                            data={timeSeries}
                                            margin={{
                                                top: 10,
                                                right: 10,
                                                left: -20,
                                                bottom: 0,
                                            }}
                                        >
                                            <defs>
                                                <linearGradient
                                                    id="colorAllowed"
                                                    x1="0"
                                                    y1="0"
                                                    x2="0"
                                                    y2="1"
                                                >
                                                    <stop
                                                        offset="5%"
                                                        stopColor="#3b82f6"
                                                        stopOpacity={0.3}
                                                    />
                                                    <stop
                                                        offset="95%"
                                                        stopColor="#3b82f6"
                                                        stopOpacity={0}
                                                    />
                                                </linearGradient>
                                                <linearGradient
                                                    id="colorThreat"
                                                    x1="0"
                                                    y1="0"
                                                    x2="0"
                                                    y2="1"
                                                >
                                                    <stop
                                                        offset="5%"
                                                        stopColor="#ef4444"
                                                        stopOpacity={0.3}
                                                    />
                                                    <stop
                                                        offset="95%"
                                                        stopColor="#ef4444"
                                                        stopOpacity={0}
                                                    />
                                                </linearGradient>
                                                <linearGradient
                                                    id="colorChallenge"
                                                    x1="0"
                                                    y1="0"
                                                    x2="0"
                                                    y2="1"
                                                >
                                                    <stop
                                                        offset="5%"
                                                        stopColor="#f59e0b"
                                                        stopOpacity={0.3}
                                                    />
                                                    <stop
                                                        offset="95%"
                                                        stopColor="#f59e0b"
                                                        stopOpacity={0}
                                                    />
                                                </linearGradient>
                                            </defs>
                                            <CartesianGrid
                                                strokeDasharray="3 3"
                                                vertical={false}
                                                stroke="rgba(255,255,255,0.03)"
                                            />
                                            <XAxis
                                                dataKey="time"
                                                axisLine={false}
                                                tickLine={false}
                                                tick={{
                                                    fontSize: 9,
                                                    fill: 'rgba(255,255,255,0.4)',
                                                    fontWeight: 600,
                                                }}
                                                minTickGap={60}
                                                tickFormatter={(str) => {
                                                    const date = new Date(str);

                                                    return date.toLocaleTimeString(
                                                        [],
                                                        {
                                                            hour: '2-digit',
                                                            minute: '2-digit',
                                                        },
                                                    );
                                                }}
                                            />
                                            <YAxis
                                                axisLine={false}
                                                tickLine={false}
                                                tick={{
                                                    fontSize: 9,
                                                    fill: 'rgba(255,255,255,0.4)',
                                                    fontWeight: 600,
                                                }}
                                            />
                                            <Tooltip
                                                content={({
                                                    active,
                                                    payload,
                                                    label,
                                                }) => {
                                                    if (
                                                        active &&
                                                        payload &&
                                                        payload.length
                                                    ) {
                                                        return (
                                                            <div className="animate-in rounded-xl border border-white/10 bg-[#09090b] p-4 shadow-2xl backdrop-blur-xl duration-200 fade-in zoom-in">
                                                                <p className="mb-3 border-b border-white/5 pb-2 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                                                    {label
                                                                        ? new Date(
                                                                              label,
                                                                          ).toLocaleString()
                                                                        : ''}
                                                                </p>
                                                                <div className="space-y-2">
                                                                    {payload.map(
                                                                        (
                                                                            entry: any,
                                                                            index: number,
                                                                        ) => (
                                                                            <div
                                                                                key={
                                                                                    index
                                                                                }
                                                                                className="flex items-center justify-between gap-8"
                                                                            >
                                                                                <div className="flex items-center gap-2">
                                                                                    <div
                                                                                        className="h-1.5 w-1.5 rounded-full"
                                                                                        style={{
                                                                                            backgroundColor:
                                                                                                entry.color,
                                                                                        }}
                                                                                    />
                                                                                    <span className="text-[11px] font-bold text-foreground/80">
                                                                                        {
                                                                                            entry.name
                                                                                        }
                                                                                    </span>
                                                                                </div>
                                                                                <span className="text-[11px] font-black text-foreground">
                                                                                    {entry.value.toLocaleString()}
                                                                                </span>
                                                                            </div>
                                                                        ),
                                                                    )}
                                                                </div>
                                                            </div>
                                                        );
                                                    }

                                                    return null;
                                                }}
                                            />
                                            <Area
                                                type="monotone"
                                                dataKey="allowed"
                                                name="Allowed"
                                                stroke="#3b82f6"
                                                strokeWidth={3}
                                                fill="url(#colorAllowed)"
                                                stackId="1"
                                                activeDot={{
                                                    r: 6,
                                                    strokeWidth: 0,
                                                    fill: '#3b82f6',
                                                }}
                                            />
                                            <Area
                                                type="monotone"
                                                dataKey="denied"
                                                name="Blocked"
                                                stroke="#ef4444"
                                                strokeWidth={3}
                                                fill="url(#colorThreat)"
                                                stackId="2"
                                                activeDot={{
                                                    r: 6,
                                                    strokeWidth: 0,
                                                    fill: '#ef4444',
                                                }}
                                            />
                                            <Area
                                                type="monotone"
                                                dataKey="challenged"
                                                name="Challenged"
                                                stroke="#f59e0b"
                                                strokeWidth={3}
                                                fill="url(#colorChallenge)"
                                                stackId="3"
                                                activeDot={{
                                                    r: 6,
                                                    strokeWidth: 0,
                                                    fill: '#f59e0b',
                                                }}
                                            />
                                        </AreaChart>
                                    </ResponsiveContainer>
                                </CardContent>
                            </Card>

                            <Card className="border-border bg-card shadow-2xl lg:col-span-4">
                                <CardHeader>
                                    <CardTitle className="flex items-center gap-2 text-[10px] font-black tracking-widest text-muted-foreground uppercase">
                                        <AlertTriangle className="size-3.5 text-orange-500" />
                                        Recent Threats
                                    </CardTitle>
                                </CardHeader>
                                <CardContent className="p-0">
                                    <div className="divide-y divide-border/50">
                                        {recentAlerts.length > 0 ? (
                                            recentAlerts.map((alert: any) => (
                                                <Link
                                                    key={alert.id}
                                                    href={securityThreatHref(
                                                        alert.hash,
                                                    )}
                                                    className="group flex items-center justify-between p-4 transition-all hover:bg-muted/50"
                                                >
                                                    <div className="flex flex-col gap-0.5">
                                                        <div className="text-[11px] font-bold text-foreground transition-colors group-hover:text-primary">
                                                            {alert.title}
                                                        </div>
                                                        <div className="flex items-center gap-1 text-[9px] text-muted-foreground">
                                                            <Activity className="size-2.5" />
                                                            {new Date(
                                                                alert.last_seen_at,
                                                            ).toLocaleTimeString(
                                                                [],
                                                                {
                                                                    hour: '2-digit',
                                                                    minute: '2-digit',
                                                                },
                                                            )}
                                                        </div>
                                                    </div>
                                                    <div className="flex h-6 w-6 items-center justify-center rounded-full bg-muted opacity-0 transition-all group-hover:opacity-100">
                                                        <ChevronRight className="size-3 text-muted-foreground" />
                                                    </div>
                                                </Link>
                                            ))
                                        ) : (
                                            <div className="p-12 text-center">
                                                <div className="mx-auto mb-3 flex h-10 w-10 items-center justify-center rounded-full bg-emerald-500/10 text-emerald-500">
                                                    <ShieldCheck className="size-5" />
                                                </div>
                                                <p className="text-[10px] font-bold tracking-widest text-muted-foreground uppercase">
                                                    No Active Threats
                                                </p>
                                            </div>
                                        )}
                                    </div>
                                    <div className="border-t border-border/50 bg-muted/20 p-4">
                                        <Link
                                            href={`/${teamSlug}/${projectSlug}/firewall/audit`}
                                            className="flex items-center justify-center gap-1 text-[9px] font-black tracking-widest text-primary uppercase hover:underline"
                                        >
                                            View Full Audit Log{' '}
                                            <ArrowDownRight className="size-3" />
                                        </Link>
                                    </div>
                                </CardContent>
                            </Card>
                        </div>

                        {/* Bottom Grid: Protection Overview */}
                        <div className="grid grid-cols-1 gap-6 md:grid-cols-3">
                            {[
                                {
                                    title: 'WAF Protection',
                                    status: true,
                                    icon: Shield,
                                    desc: 'Advanced rule engine active',
                                },
                                {
                                    title: 'Browser Check',
                                    status: settings.browser_check,
                                    icon: Globe,
                                    desc: 'JS integrity verification',
                                },
                                {
                                    title: 'Hotlink Shield',
                                    status: settings.hotlink_protection,
                                    icon: LockIcon,
                                    desc: 'Asset protection enabled',
                                },
                            ].map((item, i) => (
                                <Card
                                    key={i}
                                    className="border-border bg-card shadow-lg transition-all hover:-translate-y-1 hover:shadow-xl"
                                >
                                    <CardContent className="flex items-start gap-4 p-6">
                                        <div
                                            className={`flex h-10 w-10 items-center justify-center rounded-xl ${item.status ? 'border border-emerald-500/20 bg-emerald-500/10 text-emerald-500' : 'border border-border bg-muted text-muted-foreground'}`}
                                        >
                                            <item.icon className="size-5" />
                                        </div>
                                        <div className="space-y-1">
                                            <h3 className="text-xs font-black tracking-tight uppercase">
                                                {item.title}
                                            </h3>
                                            <p className="text-[10px] font-medium text-muted-foreground">
                                                {item.desc}
                                            </p>
                                            <Badge
                                                className={`h-4 border-none px-1.5 text-[8px] font-black ${item.status ? 'bg-emerald-500' : 'bg-muted text-muted-foreground'}`}
                                            >
                                                {item.status ? 'ACTIVE' : 'OFF'}
                                            </Badge>
                                        </div>
                                    </CardContent>
                                </Card>
                            ))}
                        </div>
                    </div>
                )}
            </div>
        </div>
    );
}

FirewallOverview.layout = (page: any) => (
    <AppLayout
        children={page}
        breadcrumbs={[
            { title: 'Firewall', href: '#' },
            { title: 'Overview', href: '#' },
        ]}
    />
);
